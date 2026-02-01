#!/bin/bash
set -e

# Backup script for Redis data
# Encrypts using JWT_SECRET as the encryption password

BACKUP_DIR="/backups"
DATE=$(date +%Y-%m-%d)
BACKUP_FILE="${BACKUP_DIR}/backup-${DATE}.json"
ENCRYPTED_FILE="${BACKUP_DIR}/backup-${DATE}.enc.json"
TEMP_FILE="/tmp/backup-${DATE}.json"

# Get Redis data using redis-cli
echo "Starting backup at $(date)"
echo "Scanning Redis for persistent data..."

# Create JSON structure
echo '{' > "$TEMP_FILE"
echo "  \"backup_date\": \"$(date -Iseconds)\"," >> "$TEMP_FILE"
echo '  "data": [' >> "$TEMP_FILE"

FIRST=true

# Function to escape strings for JSON
json_escape() {
    printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()), end="")' 2>/dev/null || printf '"%s"' "$1"
}

# Get all keys matching persistent data patterns
# locked:*, perm:*, advertise:*, stats:*
for PATTERN in "locked:*" "perm:*" "advertise:*" "stats:*"; do
    echo "Processing pattern: $PATTERN"
    
    # Use SCAN to iterate through keys
    cursor="0"
    while true; do
        result=$(redis-cli -h redis SCAN $cursor MATCH "$PATTERN" COUNT 100)
        cursor=$(echo "$result" | head -1)
        keys=$(echo "$result" | tail -n +2)
        
        if [ -z "$keys" ] || [ "$keys" = "" ]; then
            break
        fi
        
        for key in $keys; do
            if [ -z "$key" ]; then
                continue
            fi
            
            # Determine key type
            key_type=$(redis-cli -h redis TYPE "$key" | tr -d '\r\n')
            
            case "$key_type" in
                "string")
                    value=$(redis-cli -h redis GET "$key" | tr -d '\r\n')
                    if [ -n "$value" ]; then
                        if [ "$FIRST" = true ]; then
                            FIRST=false
                        else
                            echo "," >> "$TEMP_FILE"
                        fi
                        printf '    {"key": %s, "type": "string", "value": %s}' "$(json_escape "$key")" "$(json_escape "$value")" >> "$TEMP_FILE"
                    fi
                    ;;
                "set")
                    members=$(redis-cli -h redis SMEMBERS "$key" | tr -d '\r\n')
                    if [ -n "$members" ]; then
                        if [ "$FIRST" = true ]; then
                            FIRST=false
                        else
                            echo "," >> "$TEMP_FILE"
                        fi
                        # Convert members to JSON array
                        members_json=$(echo "$members" | python3 -c 'import json,sys; lines=[l.strip() for l in sys.stdin if l.strip()]; print(json.dumps(lines))' 2>/dev/null || echo "[]")
                        printf '    {"key": %s, "type": "set", "value": %s}' "$(json_escape "$key")" "$members_json" >> "$TEMP_FILE"
                    fi
                    ;;
                "hash"|"list"|"zset")
                    # Handle other types if needed
                    ;;
            esac
        done
        
        if [ "$cursor" = "0" ]; then
            break
        fi
    done
done

# Close JSON structure
echo '' >> "$TEMP_FILE"
echo '  ]' >> "$TEMP_FILE"
echo '}' >> "$TEMP_FILE"

# Encrypt the backup file using JWT_SECRET
echo "Encrypting backup file..."
openssl enc -aes-256-cbc -salt -in "$TEMP_FILE" -out "$ENCRYPTED_FILE" -pass env:JWT_SECRET

# Clean up temp file
rm -f "$TEMP_FILE"

# Set permissions
chmod 600 "$ENCRYPTED_FILE"

echo "Backup completed: $ENCRYPTED_FILE"
