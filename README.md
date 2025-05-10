# Docker Firewall Manager

A web interface to manage Docker firewall rules (DOCKER-USER chain in iptables), packaged as a Docker container.

## Features

- View all current DOCKER-USER chain rules in a user-friendly interface
- Add new rules with specific ports and source IP addresses
- Delete existing rules
- Flush all rules from the DOCKER-USER chain
- Save rules persistently
- Raw output view for debugging

## Running with Docker

The application must run with special privileges to access and modify iptables rules on the host.

### Using Docker Compose (Recommended)

1. Clone this repository
2. Run with docker-compose:

```bash
docker-compose up -d
```

### Using Docker Run

```bash
docker build -t docker-firewall-manager .
docker run -d --name firewall-manager \
  --cap-add=NET_ADMIN \
  --privileged \
  --network=host \
  -p 8000:8000 \
  -v /etc/iptables:/etc/iptables \
  docker-firewall-manager
```

## Accessing the Web Interface

Once the container is running, access the web interface at:

```
http://localhost:8000

# Authentication credentials
AUTH_USERNAME = "admin"
AUTH_PASSWORD = "123"

# You can change the password from the file app.py.
```

## Required Docker Privileges

This container requires special privileges:

- `--cap-add=NET_ADMIN`: Allows the container to modify network settings
- `--privileged`: Gives extended privileges to the container
- `--network=host`: Uses the host network stack, required for proper iptables access

## Directory Structure

```
docker-firewall-manager/
├── app.py                 # Flask application
├── Dockerfile             # Docker image definition
├── docker-compose.yml     # Docker Compose configuration
├── requirements.txt       # Python dependencies
├── startup.sh            # Container startup script
└── templates/            # HTML templates
    ├── index.html        # Main UI template
    └── error.html        # Error page template
```

## Security Considerations

- This container runs with privileged access to maintain firewall rules
- Consider restricting access to the web interface through network settings
- Verify all rules before applying them to prevent locking yourself out
- Use a proper authentication method if exposing beyond localhost

## Troubleshooting

If you encounter issues:

1. Check container logs:
```bash
docker logs firewall-manager
```

2. Verify the container has proper privileges:
```bash
docker exec firewall-manager iptables -L -n
```

3. Check if the DOCKER-USER chain exists:
```bash
docker exec firewall-manager iptables -L DOCKER-USER -n
```
