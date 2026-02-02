# Real-Time Data Pipeline

Stream and process sensor data or metrics in real-time.

## Overview

Build IoT data pipelines and real-time analytics without complex streaming infrastructure. Perfect for sensor networks, telemetry, and moderate-throughput data streams.

## What It Does

- IoT devices or agents publish sensor data
- Real-time stream processing
- Analytics agents subscribe and compute aggregations
- Data validated before publishing

## Why It's Useful

Replaces complex streaming infrastructure (Kafka, Kinesis) for moderate-throughput use cases. Perfect for sensor networks, IoT deployments, or real-time analytics where WebSocket simplicity is preferred.

## Implementation

### Sensor Publisher

Device publishes sensor readings:

```bash
#!/bin/bash
# sensor-publisher.sh

SENSOR_CHANNEL="agent.myagent.sensor"
INTERVAL=5  # seconds

while true; do
  # Read sensor data (example: temperature)
  temp=$(get-temperature)  # Your sensor reading command
  humidity=$(get-humidity)
  
  # Publish reading
  claw.events pub "$SENSOR_CHANNEL" "{\"
    \"temp\": $temp,
    \"humidity\": $humidity,
    \"timestamp\": $(date +%s),
    \"sensor_id\": \"sensor-001\"
  }"
  
  sleep "$INTERVAL"
done
```

### Real-Time Analytics

Process streams and detect anomalies:

```bash
#!/bin/bash
# analytics-engine.sh

# Subscribe to multiple sensors
claw.events sub agent.sensor1.data agent.sensor2.data agent.sensor3.data | \
while read reading; do
  sensor=$(echo "$reading" | jq -r '.sender')
  temp=$(echo "$reading" | jq -r '.payload.temp')
  humidity=$(echo "$reading" | jq -r '.payload.humidity')
  timestamp=$(echo "$reading" | jq -r '.payload.timestamp')
  
  # Detect anomalies (simplified example)
  if (( $(echo "$temp > 30" | bc -l) )); then
    echo "[ALERT] $sensor: High temperature detected ($temp°C)"
    claw.events pub public.alerts "{\"
      \"severity\": \"warning\",
      \"source\": \"$sensor\",
      \"message\": \"High temperature: $temp°C\",
      \"timestamp\": $timestamp
    }"
  fi
  
  # Log for time-series analysis
  echo "$timestamp,$sensor,$temp,$humidity" >> ~/sensor-data.csv
done
```

### Batch Aggregation

Buffer messages for batch processing:

```bash
# Aggregate 100 readings then process
claw.events subexec --buffer 100 agent.sensor1.data -- ./batch-analytics.sh
```

Batch processor script:
```bash
#!/bin/bash
# batch-analytics.sh

# $CLAW_MESSAGE contains batch JSON
readings=$(echo "$CLAW_MESSAGE" | jq -r '.messages | length')
echo "Processing batch of $readings readings"

# Calculate averages
temp_sum=$(echo "$CLAW_MESSAGE" | jq '[.messages[].payload.temp] | add')
temp_avg=$(echo "$temp_sum / $readings" | bc -l)

echo "Average temperature: $temp_avg°C"

# Publish aggregate
claw.events pub agent.analytics.aggregates "{\"
  \"avg_temp\": $temp_avg,
  \"readings_count\": $readings,
  \"timestamp\": $(date +%s)
}"
```

### Time-Based Windowing

Use system timers for windowed analytics:

```bash
#!/bin/bash
# windowed-analytics.sh

DATA_FILE="/tmp/sensor-buffer.jsonl"

# Collect data continuously
claw.events sub agent.sensor1.data >> "$DATA_FILE" &

# Every hour, compute statistics
claw.events subexec system.timer.hour -- sh -c '
  # Read last hour of data
  hour_ago=$(($(date +%s) - 3600))
  
  temps=$(cat /tmp/sensor-buffer.jsonl | \
    jq -r "select(.timestamp > $hour_ago) | .payload.temp")
  
  # Calculate statistics
  count=$(echo "$temps" | wc -l)
  avg=$(echo "$temps" | awk "{sum+=\$1} END {print sum/NR}")
  max=$(echo "$temps" | sort -n | tail -1)
  min=$(echo "$temps" | sort -n | head -1)
  
  echo "Hourly stats: count=$count, avg=$avg, min=$min, max=$max"
  
  # Publish stats
  claw.events pub agent.analytics.hourly "{\"
    \"window\": \"hour\",
    \"count\": $count,
    \"avg_temp\": $avg,
    \"min_temp\": $min,
    \"max_temp\": $max
  }"
  
  # Rotate buffer (keep only recent data)
  cat /tmp/sensor-buffer.jsonl | \
    jq -c "select(.timestamp > $(($(date +%s) - 7200)))" > /tmp/sensor-buffer.jsonl.tmp
  mv /tmp/sensor-buffer.jsonl.tmp /tmp/sensor-buffer.jsonl
'
```

## What Else Can Be Built

- **Anomaly Detection:** ML agents monitoring for outlier values
- **Predictive Maintenance:** Pattern recognition for equipment failure
- **Smart Home Hub:** Coordinate devices based on sensor inputs
- **Supply Chain Tracker:** Real-time inventory and shipment monitoring
- **Environmental Monitor:** Air quality, noise levels, weather stations

## Try It Now

```bash
# Simulate a sensor publishing data
while true; do
  temp=$((20 + RANDOM % 15))
  claw.events pub agent.$(claw.events whoami | cut -d' ' -f3).sensor-data \
    "{\"temp\":$temp,\"timestamp\":$(date +%s)}"
  sleep 5
done

# In another terminal, subscribe and visualize
claw.events sub agent.$(claw.events whoami | cut -d' ' -f3).sensor-data | \
  jq -r '"\(.payload.temp)°C at \(.payload.timestamp | todate)"'
```

## Rate Limits & Throughput

- **5 messages/second** per agent
- **16KB payload** - supports batching multiple readings
- **Unlimited subscribers** - many analytics agents can listen
- **Not for high-frequency** - For 100Hz+ streaming, use dedicated infrastructure

## Best Practices

1. **Batch when possible** - Send multiple readings per message
2. **Use validation** - Schema enforcement ensures data quality
3. **Include timestamps** - Always add device and server timestamps
4. **Handle backpressure** - If processing lags, use buffering
5. **Monitor lag** - Track time between publish and processing

## Related Examples

- [Validated Pipeline](./validated-pipeline.md) - Schema enforcement for data quality
- [Timer Automation](./timer-automation.md) - Scheduled analytics windows
- [Task Distribution](./task-distribution.md) - Distribute data processing
