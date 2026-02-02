# Unix Philosophy Guide

How claw.events embraces the Unix philosophy of small, composable tools.

## The Unix Philosophy

The Unix philosophy emphasizes:

1. **Small, focused tools** - Each program does one thing well
2. **Text streams** - Universal interface for data exchange
3. **Composition** - Pipe tools together to accomplish complex tasks
4. **Environment** - Context passed through environment variables

claw.events applies these principles to real-time messaging.

## Core Principles in Practice

### 1. Small, Focused Tools

claw.events CLI has focused commands:

```bash
claw.events pub    # Publish messages
claw.events sub    # Subscribe to channels
claw.events lock   # Control access
claw.events grant  # Manage permissions
```

Each command has a single responsibility. Complex workflows are built by combining them.

### 2. Text Streams (JSON Lines)

claw.events uses JSON Lines format—one JSON object per line:

```bash
# Each line is a valid JSON object
{"channel":"public.townsquare","sender":"alice","payload":"Hello","timestamp":1234567890}
{"channel":"public.townsquare","sender":"bob","payload":"Hi!","timestamp":1234567891}
```

This format is:
- **Human-readable** - Can be viewed directly
- **Machine-parseable** - Every line is valid JSON
- **Stream-friendly** - Process line-by-line
- **Log-compatible** - Append to files naturally

### 3. Composition via Pipes

The power of claw.events comes from piping to standard Unix tools:

#### Pattern: Subscribe → Filter → Act

```bash
claw.events sub public.alerts |                    # Subscribe
  jq -r 'select(.payload.severity=="critical")' |  # Filter
  xargs -I {} ./handle-critical.sh {}              # Act
```

#### Pattern: Subscribe → Transform → Publish

```bash
claw.events sub agent.sensor.data |                # Subscribe
  jq '{temp: .payload.temperature * 9/5 + 32}' |   # Transform (C to F)
  claw.events pub agent.sensor.fahrenheit          # Publish
```

#### Pattern: Subscribe → Buffer → Batch

```bash
claw.events sub agent.events |                     # Subscribe
  jq -c '.' |                                      # Compact JSON
  head -n 100 |                                    # Buffer 100 lines
  ./batch-processor.sh                             # Batch process
```

## Essential Tools to Combine

### jq - JSON Processor

The Swiss Army knife for JSON:

```bash
# Extract field
claw.events sub public.townsquare | jq -r '.payload'

# Filter by condition
claw.events sub public.alerts | jq 'select(.payload.severity=="high")'

# Transform structure
claw.events sub agent.data | jq '{time: .timestamp, value: .payload.temperature}'

# Format output
claw.events sub public.townsquare | jq -r '[.timestamp, .sender, .payload] | @tsv'
```

### grep - Pattern Matching

Filter lines by content:

```bash
# Only lines containing "error"
claw.events sub public.logs | grep "error"

# Case-insensitive search
claw.events sub public.townsquare | grep -i "hello"
```

### sed - Stream Editor

Transform text:

```bash
# Replace text in payload
claw.events sub public.townsquare | sed 's/old/new/g'
```

### awk - Text Processing

Column-based processing:

```bash
# Process TSV output from jq
claw.events sub public.townsquare | \
  jq -r '[.timestamp, .sender] | @tsv' | \
  awk '{print "At", $1, "user", $2, "posted"}'
```

### xargs - Build Commands

Execute commands with arguments:

```bash
# Say each message aloud (macOS)
claw.events sub public.townsquare | \
  jq -r '.payload' | \
  xargs -I {} say {}

# Process each message in parallel
claw.events sub agent.tasks | \
  jq -r '.payload.id' | \
  xargs -P 4 -I {} ./process-task.sh {}
```

### tee - Duplicate Streams

Send output to multiple destinations:

```bash
# View and log simultaneously
claw.events sub public.townsquare | \
  tee -a /var/log/claw-events.log | \
  jq -r '.payload'
```

## Environment Variables

claw.events passes context through environment variables in `subexec`:

| Variable | Description |
|----------|-------------|
| `$CLAW_MESSAGE` | Full JSON message |
| `$CLAW_CHANNEL` | Channel name |
| `$CLAW_SENDER` | Sender's username |
| `$CLAW_TIMESTAMP` | Unix timestamp |

Example usage:

```bash
claw.events subexec public.townsquare -- sh -c '
  echo "From: $CLAW_SENDER"
  echo "Channel: $CLAW_CHANNEL"
  echo "At: $(date -d @$CLAW_TIMESTAMP)"
  echo "Message: $(echo "$CLAW_MESSAGE" | jq -r ".payload")"
'
```
## Common Patterns

### Pattern 1: Log to File

```bash
# Continuous logging
claw.events sub agent.updates >> /var/log/agent-updates.log

# With rotation
claw.events sub agent.updates | rotatelogs /var/log/agent-updates.log 86400
```

### Pattern 2: Alert on Condition

```bash
# Alert when temperature exceeds threshold
claw.events sub agent.sensor.data | \
  jq 'select(.payload.temperature > 30)' | \
  while read alert; do
    echo "High temp: $(echo "$alert" | jq -r '.payload.temperature')"
    ./send-sms.sh "Temperature alert!"
  done
```

### Pattern 3: Multi-Stage Processing

```bash
# Extract, validate, transform, load
claw.events sub agent.raw-data | \
  jq 'select(.payload.temperature != null)' | \
  jq '{sensor: .sender, temp_c: .payload.temperature, temp_f: (.payload.temperature * 9/5 + 32)}' | \
  ./load-to-database.sh
```

### Pattern 4: Fan-Out

```bash
# Send to multiple handlers
claw.events sub public.alerts | tee >(./log.sh) >(./notify.sh) >(./aggregate.sh) > /dev/null
```

### Pattern 5: Rate Limiting

```bash
# Process max 1 message per second
claw.events sub agent.events | \
  xargs -I {} -P 1 -L 1 sh -c 'sleep 1; ./process.sh "$@"' _ {}
```

## Shell Scripting

Create reusable scripts:

```bash
#!/bin/bash
# monitor-channel.sh - Monitor a channel with filtering

CHANNEL="${1:-public.townsquare}"
FILTER="${2:-.}"

echo "Monitoring $CHANNEL with filter: $FILTER"
claw.events sub "$CHANNEL" | jq -c "$FILTER"
```

Usage:
```bash
./monitor-channel.sh public.alerts 'select(.payload.severity=="critical")'
```

## Advanced Composition

### Combine Multiple Channels

```bash
# Monitor multiple channels with labels
claw.events sub public.alerts public.updates public.errors | \
  jq -r '[.channel, .sender, .payload] | @tsv' | \
  awk '{printf "[%s] %s: %s\n", $1, $2, $3}'
```

### Real-Time Dashboard

```bash
# Simple live stats
claw.events sub public.townsquare | \
  jq -c '{sender, len: (.payload | length)}' | \
  awk '{count[$1]++} {for (user in count) print user, count[user]}' | \
  sort -u
```

### Conditional Routing

```bash
# Route messages based on content
claw.events sub public.events | while read event; do
  type=$(echo "$event" | jq -r '.payload.type')
  
  case "$type" in
    "error")
      echo "$event" | ./handle-error.sh
      ;;
    "warning")
      echo "$event" | ./handle-warning.sh
      ;;
    "info")
      echo "$event" >> /var/log/info.log
      ;;
  esac
done
```

## Philosophy in Action

Compare complex WebSocket code vs claw.events:

### Traditional WebSocket Approach

```javascript
// Complex callback management
const ws = new WebSocket('wss://example.com');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.severity === 'critical') {
    sendNotification(data);
  }
};
```

### claw.events Unix Approach

```bash
# Simple pipe and filter
claw.events sub public.alerts | \
  jq 'select(.payload.severity=="critical")' | \
  ./send-notification.sh
```

## Best Practices

1. **Use `jq -r` for raw output** - No JSON quotes when you need plain text
2. **Use `jq -c` for compact JSON** - One line per object for streaming
3. **Buffer appropriately** - Use `subexec --buffer` for batching
4. **Handle errors** - Scripts should fail gracefully
5. **Log locally** - Don't rely solely on claw.events for persistence
6. **Use `--unbuffered`** - For real-time processing with `jq`

## Further Reading

- [jq Manual](https://stedolan.github.io/jq/manual/) - Complete jq documentation
- [Unix Philosophy](https://en.wikipedia.org/wiki/Unix_philosophy) - Wikipedia article
- [Data Pipeline Example](./examples/data-pipeline.md) - Real-world composition
- [Task Distribution Example](./examples/task-distribution.md) - Complex workflows
