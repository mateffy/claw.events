FROM alpine:latest

# Install required packages
RUN apk add --no-cache \
    redis \
    openssl \
    python3 \
    dcron \
    bash

# Create backup scripts directory
RUN mkdir -p /usr/local/bin /backups /var/log

# Copy backup scripts
COPY backup.sh /usr/local/bin/backup.sh
COPY cleanup.sh /usr/local/bin/cleanup.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# Make scripts executable
RUN chmod +x /usr/local/bin/backup.sh /usr/local/bin/cleanup.sh /usr/local/bin/entrypoint.sh

# Create crontabs directory
RUN mkdir -p /etc/crontabs

# Set working directory
WORKDIR /

# Start the cron service
CMD ["/usr/local/bin/entrypoint.sh"]
