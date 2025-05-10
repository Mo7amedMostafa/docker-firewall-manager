FROM python:3.9-slim

# Install required packages
RUN apt-get update && apt-get install -y \
    iptables \
    netfilter-persistent \
    procps \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /app

# Copy requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application
COPY app.py .
COPY templates/ templates/

# Volume for persistent configuration
VOLUME ["/etc/iptables"]

# Run the application
CMD ["python", "app.py"]

# Container needs to run with NET_ADMIN capability and in privileged mode
# to be able to modify iptables rules on the host
# Usage: docker run --cap-add=NET_ADMIN --network=host --privileged -v /etc/iptables:/etc/iptables [image]