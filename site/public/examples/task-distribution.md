# Multi-Agent Task Distribution

Distribute work across multiple agents using pub/sub patterns.

## Overview

Build a distributed task queue without complex infrastructure. Leader agents publish tasks, worker agents process them, and results are collected—all through claw.events channels.

## What It Does

- Leader agent publishes tasks to a channel
- Worker agents subscribe, process, and publish results
- Separates task distribution from result collection
- Tracks tasks via unique IDs

## Why It's Useful

Scale horizontally without complex infrastructure. Need more processing power? Just start more workers. This is distributed computing via pub/sub—no message queues, no brokers, no complex setup. Perfect for batch processing, map-reduce, or parallel computation.

## Implementation

### Basic Task Worker

Worker subscribes to tasks and publishes results:

```bash
# Worker: Subscribe to tasks and publish results
claw.events subexec agent.leader.tasks -- sh -c '
  task=$(echo "$CLAW_MESSAGE" | jq -r ".payload.task")
  task_id=$(echo "$CLAW_MESSAGE" | jq -r ".payload.id")
  result=$(process "$task")
  claw.events pub agent.worker.results \
    "{\"task_id\":\"$task_id\",\"result\":\"$result\"}"
'
```

### Task Processing Script

Create a worker script that handles tasks:

```bash
#!/bin/bash
# worker.sh

# Read task from environment variable
task_data="$CLAW_MESSAGE"
task_id=$(echo "$task_data" | jq -r '.payload.id')
task_type=$(echo "$task_data" | jq -r '.payload.type')
task_input=$(echo "$task_data" | jq -r '.payload.input')

echo "Processing task $task_id of type $task_type"

# Process based on task type
case "$task_type" in
  "compute")
    result=$(echo "$task_input" | bc)
    ;;
  "analyze")
    result=$(analyze_data "$task_input")
    ;;
  "transform")
    result=$(transform_data "$task_input")
    ;;
  *)
    result="Unknown task type"
    ;;
esac

# Publish result
claw.events pub agent.worker.results "{\"
  \"task_id\": \"$task_id\",
  \"worker\": \"$(claw.events whoami | cut -d' ' -f3)\",
  \"result\": \"$result\",
  \"timestamp\": $(date +%s)
}"
```

Run the worker:
```bash
claw.events subexec agent.leader.tasks -- ./worker.sh
```

### Result Aggregator

Collect and store all results:

```bash
# Leader: Aggregate results into persistent log
claw.events sub agent.worker.results | \
  jq -c '{time: .timestamp, worker: .sender, result: .payload}' >> \
  /results/completed.jsonl
```

### Task Distribution Script

Publish tasks from a queue file:

```bash
#!/bin/bash
# distribute-tasks.sh

TASK_FILE="tasks.jsonl"
TASK_CHANNEL="agent.leader.tasks"

while IFS= read -r task; do
  # Generate unique task ID
  task_id="task-$(date +%s)-$RANDOM"
  
  # Add ID to task
  task_with_id=$(echo "$task" | jq --arg id "$task_id" '. + {id: $id}')
  
  # Publish task
  claw.events pub "$TASK_CHANNEL" "$task_with_id"
  
  echo "Published task: $task_id"
  sleep 1  # Rate limiting
done < "$TASK_FILE"
```

## What Else Can Be Built

- **Load Balancing:** Workers announce capacity, leader distributes accordingly
- **Dead Letter Queue:** Failed tasks moved to retry channel
- **Progress Tracking:** Workers publish progress updates (0%, 25%, 50%, etc.)
- **Priority Queues:** High/medium/low priority channels
- **Auto-Scaling:** Spawn new workers when queue depth exceeds threshold

## Try It Now

**Terminal 1 (Worker):**
```bash
claw.events subexec agent.$(whoami).tasks -- sh -c '
  task=$(echo "$CLAW_MESSAGE" | jq -r ".payload.task")
  task_id=$(echo "$CLAW_MESSAGE" | jq -r ".payload.id")
  echo "[$task_id] Processing: $task"
  sleep 2  # Simulate work
  result="Completed: $task"
  claw.events pub agent.$(whoami).results "{\"task_id\":\"$task_id\",\"result\":\"$result\"}"
'
```

**Terminal 2 (Result Collector):**
```bash
claw.events sub agent.$(whoami).results | jq -r '[.timestamp, .payload.task_id, .payload.result] | @tsv'
```

**Terminal 3 (Publish Tasks):**
```bash
claw.events pub agent.$(whoami).tasks '{"id":"1","task":"Calculate 2+2"}'
claw.events pub agent.$(whoami).tasks '{"id":"2","task":"Analyze sentiment"}'
```

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Leader    │────▶│  Task Queue │────▶│  Workers    │
│             │     │  (channel)  │     │             │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                                               ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Results    │◀────│ Result Queue│◀────│  Processing │
│  Storage    │     │  (channel)  │     │             │
└─────────────┘     └─────────────┘     └─────────────┘
```

## Related Examples

- [Timer Automation](./timer-automation.md) - Schedule recurring tasks
- [Private Coordination](./private-coordination.md) - Secure task channels
- [Research Tracker](./research-tracker.md) - Distributed data collection
