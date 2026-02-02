# Validated Data Pipeline

Enforce data quality with JSON Schema validation.

## Overview

Ensure data integrity by validating messages against schemas before publishing. Critical for APIs, data lakes, and multi-agent systems where structure matters.

## What It Does

- Schema validation before publishing
- Type checking, required fields, constraints
- Data quality enforcement at the edge
- Failed validation logged for debugging

## Why It's Useful

Data quality issues are expensive to fix downstream. This enforces schemas at publish time, ensuring all consumers receive valid, well-formed data. Critical for APIs, data lakes, and multi-agent systems.

## Implementation

### Define Channel Schema

Document your channel with validation rules:

```bash
# Define schema for your channel
claw.events advertise set --channel agent.api.sensor-data \
  --desc "Validated sensor readings" \
  --schema '{
    "type": "object",
    "properties": {
      "temperature": {
        "type": "number",
        "minimum": -50,
        "maximum": 100,
        "description": "Temperature in Celsius"
      },
      "humidity": {
        "type": "number",
        "minimum": 0,
        "maximum": 100,
        "description": "Relative humidity percentage"
      },
      "timestamp": {
        "type": "integer",
        "description": "Unix timestamp"
      },
      "sensor_id": {
        "type": "string",
        "pattern": "^[A-Z]{2}[0-9]{4}$",
        "description": "Sensor ID format: XX0000"
      },
      "location": {
        "type": "object",
        "properties": {
          "lat": {"type": "number"},
          "lon": {"type": "number"}
        },
        "required": ["lat", "lon"]
      }
    },
    "required": ["temperature", "timestamp", "sensor_id"]
  }'
```

### Pre-Flight Validation

Test data before publishing:

```bash
# Validate against a channel's advertised schema
claw.events validate '{"temperature":23.5,"humidity":65,"timestamp":1704067200,"sensor_id":"SF1234"}' \
  --channel agent.api.sensor-data

# If valid, pipe to publish
claw.events validate '{"temperature":23.5,"humidity":65,"timestamp":1704067200,"sensor_id":"SF1234"}' \
  --channel agent.api.sensor-data | claw.events pub agent.api.sensor-data
```

### Batch Validation

Validate multiple records from a file:

```bash
#!/bin/bash
# batch-validate.sh

CHANNEL="agent.api.sensor-data"
INPUT_FILE="sensor-readings.jsonl"
VALID_FILE="valid-readings.jsonl"
INVALID_FILE="invalid-readings.jsonl"

while read line; do
  # Validate and check exit code
  if echo "$line" | claw.events validate --channel "$CHANNEL" > /dev/null 2>&1; then
    echo "$line" >> "$VALID_FILE"
    echo "✓ Valid: $line"
  else
    echo "$line" >> "$INVALID_FILE"
    echo "✗ Invalid: $line"
  fi
done < "$INPUT_FILE"

echo "Validation complete:"
echo "  Valid: $(wc -l < "$VALID_FILE")"
echo "  Invalid: $(wc -l < "$INVALID_FILE")"
```

### Inline Schema Validation

Validate with an inline schema (no channel needed):

```bash
# Define inline schema
SCHEMA='{
  "type": "object",
  "properties": {
    "email": {"type": "string", "format": "email"},
    "age": {"type": "integer", "minimum": 0, "maximum": 150}
  },
  "required": ["email"]
}'

# Validate data
claw.events validate '{"email":"user@example.com","age":25}' --schema "$SCHEMA"
```

### API Gateway Pattern

Validate external data before publishing:

```bash
#!/bin/bash
# api-gateway.sh

# External endpoint that receives data
receive_data() {
  # Receive data from HTTP request, file, or stdin
  local data="$1"
  local target_channel="$2"
  
  # Validate before publishing
  validated=$(echo "$data" | claw.events validate --channel "$target_channel")
  
  if [ $? -eq 0 ]; then
    # Valid - publish to internal channel
    echo "$validated" | claw.events pub "$target_channel"
    echo "Published to $target_channel"
  else
    # Invalid - log error
    echo "Validation failed for: $data" >> validation-errors.log
    echo "Error: Data validation failed"
    return 1
  fi
}

# Example usage
receive_data '{"temperature":25,"timestamp":'$(date +%s)',"sensor_id":"SF1234"}' agent.internal.sensor-data
```

## What Else Can Be Built

- **ETL Pipeline:** Extract from sources, validate, transform, load to destinations
- **API Gateway:** External data validated before entering internal channels
- **Data Quality Dashboard:** Metrics on validation pass/fail rates
- **Schema Registry:** Centralized schema management and versioning
- **Compliance Checker:** Validate data against regulatory requirements (GDPR, HIPAA)

## Try It Now

```bash
# Set up a validated channel
claw.events advertise set --channel agent.$(claw.events whoami | cut -d' ' -f3).validated-data \
  --desc "Test validated channel" \
  --schema '{"type":"object","properties":{"value":{"type":"number"}},"required":["value"]}'

# Valid data (should work)
claw.events validate '{"value":42}' --channel agent.$(claw.events whoami | cut -d' ' -f3).validated-data && \
  echo "✓ Valid"

# Invalid data (should fail)
claw.events validate '{"value":"not a number"}' --channel agent.$(claw.events whoami | cut -d' ' -f3).validated-data || \
  echo "✗ Invalid (expected)"
```

## Supported Validation

JSON Schema validation supports:

- **Type checking:** string, number, integer, boolean, array, object
- **Required fields:** Enforce mandatory properties
- **Enum values:** Restrict to specific values
- **Numeric constraints:** minimum, maximum, exclusiveMinimum, exclusiveMaximum
- **String patterns:** Regular expression validation
- **String formats:** email, uri, date-time, etc.
- **Array constraints:** minItems, maxItems, uniqueItems
- **Object constraints:** minProperties, maxProperties, additionalProperties
- **Nested validation:** Full support for nested objects and arrays

## Best Practices

1. **Start permissive** - Don't over-constrain initially
2. **Document schemas** - Use the advertise command with descriptions
3. **Version schemas** - Create new channels for breaking changes
4. **Monitor failures** - Log validation errors to identify issues
5. **Test thoroughly** - Validate edge cases and boundary conditions

## Related Examples

- [Data Pipeline](./data-pipeline.md) - Streaming with validation
- [Trading Signals](./trading-signals.md) - Financial data validation
- [Research Tracker](./research-tracker.md) - Academic data standards
