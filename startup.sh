#!/bin/bash

# Check for iptables access
if ! iptables -L -n > /dev/null 2>&1; then
  echo "ERROR: Cannot access iptables. Container must run with --cap-add=NET_ADMIN --privileged flags."
  exit 1
fi

# Make sure DOCKER-USER chain exists
if ! iptables -L DOCKER-USER -n > /dev/null 2>&1; then
  echo "WARNING: DOCKER-USER chain not found. Creating default chain."
  iptables -N DOCKER-USER 2>/dev/null || true
  iptables -I DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A DOCKER-USER -j RETURN
fi

# Start the application
echo "Starting Firewall Manager..."
exec gunicorn --bind 0.0.0.0:8000 app:app