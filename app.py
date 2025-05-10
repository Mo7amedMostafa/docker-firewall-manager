from flask import Flask, render_template, request, redirect, url_for, jsonify, Response
import subprocess
import re
import os
import functools
from base64 import b64decode

app = Flask(__name__)

# Authentication credentials
AUTH_USERNAME = "admin"
AUTH_PASSWORD = "123"

def check_auth(username, password):
    """Check if the provided credentials are valid"""
    return username == AUTH_USERNAME and password == AUTH_PASSWORD

def authenticate():
    """Send 401 response that enables basic auth"""
    return Response(
        'Could not verify your credentials. Please authenticate.',
        401,
        {'WWW-Authenticate': 'Basic realm="Docker Firewall Manager"'}
    )

def requires_auth(f):
    """Decorator for views that require authentication"""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return authenticate()
        
        try:
            auth_type, auth_info = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                return authenticate()
                
            auth_decoded = b64decode(auth_info).decode('utf-8')
            username, password = auth_decoded.split(':', 1)
            
            if check_auth(username, password):
                return f(*args, **kwargs)
        except Exception as e:
            pass
            
        return authenticate()
    return decorated

def check_sudo():
    """Check if the script is running with the required privileges"""
    try:
        # Try to execute a simple iptables command to check permissions
        subprocess.run(['iptables', '-L', '-n'], check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, PermissionError):
        return False

def get_docker_user_rules():
    """Get current Docker-USER chain rules"""
    try:
        result = subprocess.run(['iptables', '-L', 'DOCKER-USER', '-n', '--line-numbers'], 
                                capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr}"

def parse_rules(rules_output):
    """Parse iptables output into structured data"""
    lines = rules_output.strip().split('\n')
    
    # Skip header lines
    data_lines = [line for line in lines if line and not line.startswith('Chain') and not line.startswith('num')]
    
    parsed_rules = []
    for line in data_lines:
        # Extract line number
        match = re.match(r'(\d+)', line)
        if not match:
            continue
            
        line_num = match.group(1)
        parts = re.split(r'\s+', line.strip())
        
        # Extract common fields
        rule = {
            'num': line_num,
            'target': parts[1] if len(parts) > 1 else '',
            'prot': parts[2] if len(parts) > 2 else '',
            'source': parts[4] if len(parts) > 4 else '',
            'destination': parts[5] if len(parts) > 5 else '',
            'raw': line
        }
        
        # Extract port information from comments and options
        port_match = re.search(r'dpt:(\d+)', line)
        if port_match:
            rule['port'] = port_match.group(1)
        else:
            rule['port'] = ''
            
        # Try to extract ctorigdstport information
        ctport_match = re.search(r'ctorigdstport (\d+)', line)
        if ctport_match:
            rule['port'] = ctport_match.group(1)
        
        parsed_rules.append(rule)
    
    return parsed_rules

def find_return_rule_position():
    """Find the position of the RETURN rule in the DOCKER-USER chain"""
    try:
        rules_output = get_docker_user_rules()
        parsed_rules = parse_rules(rules_output)
        
        for rule in parsed_rules:
            if rule['target'] == 'RETURN':
                return int(rule['num'])
        
        # If no RETURN rule exists, return None
        return None
    except Exception as e:
        return None

def add_rule(port, source_ip, protocol='tcp', action='ACCEPT'):
    """Add a new rule to the DOCKER-USER chain in the correct position"""
    try:
        rules_output = get_docker_user_rules()
        parsed_rules = parse_rules(rules_output)

        insert_position = None

        # Find the first DROP rule for this port
        for rule in parsed_rules:
            if rule['port'] == port and rule['target'] == 'DROP':
                insert_position = int(rule['num'])
                break

        # If no DROP rule, fallback to inserting before RETURN
        if insert_position is None:
            insert_position = find_return_rule_position()

        # If still not found, add to the end
        if insert_position is None:
            cmd = [
                'iptables', '-A', 'DOCKER-USER',
                '-m', 'conntrack', '--ctorigdstport', port,
                '-s', source_ip, '-p', protocol, '-j', action
            ]
        else:
            cmd = [
                'iptables', '-I', 'DOCKER-USER', str(insert_position),
                '-m', 'conntrack', '--ctorigdstport', port,
                '-s', source_ip, '-p', protocol, '-j', action
            ]

        subprocess.run(cmd, capture_output=True, text=True, check=True)
        save_rules()
        return True, "Rule added successfully"
    except subprocess.CalledProcessError as e:
        return False, f"Error adding rule: {e.stderr}"

def delete_rule(rule_number):
    """Delete a rule by its line number"""
    try:
        cmd = ['iptables', '-D', 'DOCKER-USER', rule_number]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        save_rules()
        return True, "Rule deleted successfully"
    except subprocess.CalledProcessError as e:
        return False, f"Error deleting rule: {e.stderr}"

def save_rules():
    """Save the iptables rules persistently"""
    try:
        # First run netfilter-persistent save
        subprocess.run(['netfilter-persistent', 'save'], check=True, capture_output=True)
        
        # Then specifically update the rules.v4 file with the current DOCKER-USER chain
        docker_user_rules = subprocess.run(['iptables-save', '-t', 'filter'], 
                                         capture_output=True, text=True, check=True).stdout
        
        # Extract the DOCKER-USER chain
        docker_user_section = ""
        capture = False
        for line in docker_user_rules.split('\n'):
            if line.startswith(':DOCKER-USER'):
                capture = True
                docker_user_section += line + '\n'
            elif capture and line.startswith(':'):
                capture = False
            elif capture and line.startswith('-A DOCKER-USER'):
                docker_user_section += line + '\n'
        
        # Read the existing rules file
        try:
            with open('/etc/iptables/rules.v4', 'r') as f:
                rules_content = f.read()
            
            # Check if DOCKER-USER section already exists
            docker_user_pattern = r':DOCKER-USER.*?\n(?:-A DOCKER-USER.*?\n)*'
            if re.search(docker_user_pattern, rules_content, re.DOTALL):
                # Replace existing DOCKER-USER section
                updated_content = re.sub(docker_user_pattern, 
                                       docker_user_section, 
                                       rules_content, 
                                       flags=re.DOTALL)
            else:
                # Add DOCKER-USER section after the *filter line
                updated_content = rules_content.replace('*filter', '*filter\n' + docker_user_section)
            
            # Write back the updated content
            with open('/etc/iptables/rules.v4', 'w') as f:
                f.write(updated_content)
                
        except FileNotFoundError:
            # If rules.v4 doesn't exist, create it with basic structure
            complete_rules = subprocess.run(['iptables-save'], 
                                          capture_output=True, text=True, check=True).stdout
            
            with open('/etc/iptables/rules.v4', 'w') as f:
                f.write(complete_rules)
        
        return True, "Rules saved successfully to /etc/iptables/rules.v4"
    except subprocess.CalledProcessError as e:
        return False, f"Error saving rules: {e.stderr}"
    except Exception as e:
        return False, f"Error: {str(e)}"

def flush_rules():
    """Flush all rules in the DOCKER-USER chain"""
    try:
        subprocess.run(['iptables', '-F', 'DOCKER-USER'], check=True)
        subprocess.run(['iptables', '-I', 'DOCKER-USER', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT' ], check=True)
        subprocess.run(['iptables', '-A', 'DOCKER-USER', '-j', 'RETURN'], check=True)
        save_rules()
        return True, "Rules flushed successfully"
    except subprocess.CalledProcessError as e:
        return False, f"Error flushing rules: {e.stderr}"

@app.route('/')
@requires_auth
def index():
    if not check_sudo():
        return render_template('error.html', 
                              error="This application doesn't have sufficient privileges to manage iptables. Make sure the container is running with --cap-add=NET_ADMIN --privileged flags.")
    
    rules_output = get_docker_user_rules()
    parsed_rules = parse_rules(rules_output)
    
    return render_template('index.html', 
                          rules=parsed_rules, 
                          raw_output=rules_output)

@app.route('/api/rules')
@requires_auth
def api_rules():
    rules_output = get_docker_user_rules()
    parsed_rules = parse_rules(rules_output)
    return jsonify(parsed_rules)

@app.route('/api/add_rule', methods=['POST'])
@requires_auth
def api_add_rule():
    port = request.form.get('port')
    source_ip = request.form.get('source_ip')
    protocol = request.form.get('protocol', 'tcp')
    action = request.form.get('action', 'ACCEPT')
    
    success, message = add_rule(port, source_ip, protocol, action)
    return jsonify({'success': success, 'message': message})

@app.route('/api/delete_rule', methods=['POST'])
@requires_auth
def api_delete_rule():
    rule_number = request.form.get('rule_number')
    success, message = delete_rule(rule_number)
    return jsonify({'success': success, 'message': message})

@app.route('/api/flush_rules', methods=['POST'])
@requires_auth
def api_flush_rules():
    success, message = flush_rules()
    return jsonify({'success': success, 'message': message})

@app.route('/api/save_rules', methods=['POST'])
@requires_auth
def api_save_rules():
    success, message = save_rules()
    return jsonify({'success': success, 'message': message})

def get_rule_details(rule_number):
    """Get details of a specific rule by number"""
    try:
        rule_output = subprocess.run(['iptables', '-L', 'DOCKER-USER', '-n', '--line-numbers'], 
                                    capture_output=True, text=True, check=True).stdout
        
        lines = rule_output.strip().split('\n')
        # Skip header lines
        data_lines = [line for line in lines if line and not line.startswith('Chain') and not line.startswith('num')]
        
        for line in data_lines:
            # Extract line number
            match = re.match(r'(\d+)', line)
            if match and match.group(1) == rule_number:
                # Parse the rule details
                parts = re.split(r'\s+', line.strip())
                rule = {
                    'num': rule_number,
                    'target': parts[1] if len(parts) > 1 else '',
                    'prot': parts[2] if len(parts) > 2 else '',
                    'source': parts[4] if len(parts) > 4 else '',
                    'destination': parts[5] if len(parts) > 5 else '',
                    'raw': line
                }
                
                # Extract port information
                port_match = re.search(r'dpt:(\d+)', line)
                if port_match:
                    rule['port'] = port_match.group(1)
                else:
                    # Try to extract ctorigdstport information
                    ctport_match = re.search(r'ctorigdstport (\d+)', line)
                    if ctport_match:
                        rule['port'] = ctport_match.group(1)
                    else:
                        rule['port'] = ''
                
                return rule
        
        return None
    except subprocess.CalledProcessError as e:
        return None

@app.route('/api/get_rule', methods=['GET'])
@requires_auth
def api_get_rule():
    rule_number = request.args.get('rule_number')
    if not rule_number:
        return jsonify({'success': False, 'message': 'No rule number provided'})
    
    rule = get_rule_details(rule_number)
    if not rule:
        return jsonify({'success': False, 'message': f'Rule {rule_number} not found'})
    
    return jsonify({'success': True, 'rule': rule})

def edit_rule(rule_number, port, source_ip, protocol='tcp', action='ACCEPT'):
    """Edit a rule by deleting and recreating it"""
    try:
        # Check if the rule being edited is the RETURN rule
        rule = get_rule_details(rule_number)
        if rule and rule['target'] == 'RETURN':
            return False, "Cannot edit the RETURN rule"
            
        # First delete the existing rule
        delete_result = delete_rule(rule_number)
        if not delete_result[0]:
            return delete_result
        
        # Then add the new rule
        add_result = add_rule(port, source_ip, protocol, action)
        if not add_result[0]:
            return add_result
            
        save_rules()
        return True, "Rule updated successfully"
    except Exception as e:
        return False, f"Error updating rule: {str(e)}"

@app.route('/api/edit_rule', methods=['POST'])
@requires_auth
def api_edit_rule():
    rule_number = request.form.get('rule_number')
    port = request.form.get('port')
    source_ip = request.form.get('source_ip')
    protocol = request.form.get('protocol', 'tcp')
    action = request.form.get('action', 'ACCEPT')
    
    success, message = edit_rule(rule_number, port, source_ip, protocol, action)
    return jsonify({'success': success, 'message': message})

def ensure_return_rule_at_end():
    """Ensure that a RETURN rule exists at the end of the DOCKER-USER chain"""
    try:
        # Check for the RETURN rule
        return_position = find_return_rule_position()
        rules_output = get_docker_user_rules()
        parsed_rules = parse_rules(rules_output)
        
        # If no RETURN rule or it's not the last rule, fix it
        if return_position is None or return_position != len(parsed_rules):
            # If a RETURN rule exists but is not at the end, delete it
            if return_position is not None:
                delete_rule(str(return_position))
                
            # Add a RETURN rule at the end
            subprocess.run(['iptables', '-A', 'DOCKER-USER', '-j', 'RETURN'], check=True)
            save_rules()
            return True, "RETURN rule ensured at the end"
        
        return True, "RETURN rule already at the end"
    except Exception as e:
        return False, f"Error ensuring RETURN rule: {str(e)}"

if __name__ == "__main__":
    print("Starting Docker Firewall Manager...")
    if not check_sudo():
        print("WARNING: This application doesn't have sufficient privileges to manage iptables.")
        print("Make sure to run the container with --cap-add=NET_ADMIN --privileged flags.")
    
    # Ensure RETURN rule is at the end on startup
    ensure_return_rule_at_end()
    
    app.run(host='0.0.0.0', port=8000, debug=False)