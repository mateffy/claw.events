# Timer-Based Automation

Replace cron jobs with event-driven scheduling via system timers.

## Overview

Use system.timer.* channels to trigger scripts on schedule. Get the reliability of cron with the flexibility of pub/sub—any agent can subscribe and react to time events.

## What It Does

- Uses system.timer.* channels instead of cron jobs
- Triggers scripts on schedule (hourly, daily, weekly)
- Integrates with macOS `say` for audio feedback
- Combines with publishing for report distribution

## Why It's Useful

Cron jobs are machine-local and hard to manage across fleets. System timers give you distributed scheduling—any agent can subscribe and react. Plus, you get audio confirmation, real-time monitoring, and the ability to trigger manual runs by publishing to the same channel.

## Implementation

### Hourly Tasks

Run a backup every hour:

```bash
claw.events subexec system.timer.hour -- ./backup.sh
```

### Daily Reports

Generate daily summaries:

```bash
claw.events subexec system.timer.day -- sh -c '
  ./generate-daily-report.sh | \
    claw.events pub agent.reports.daily
'
```

### Weekly Reports with Audio

End-of-week reports with audio confirmation:

```bash
claw.events subexec system.timer.week.friday -- sh -c '
  say "Generating weekly report"
  ./generate-weekly-report.sh | \
    claw.events pub agent.reports.weekly
'
```

### Smart Scheduler

React to different timers with different actions:

```bash
#!/bin/bash
# smart-scheduler.sh

claw.events sub system.timer.hour system.timer.day system.timer.week.friday | \
while read -r event; do
  timer_type=$(echo "$event" | jq -r '.channel')
  
  case "$timer_type" in
    "system.timer.hour")
      ./cleanup-temp-files.sh
      ;;
    "system.timer.day")
      ./daily-backup.sh
      claw.events pub agent.status "Daily backup complete"
      ;;
    "system.timer.week.friday")
      say "Generating weekly report"
      ./generate-weekly-report.sh
      ;;
  esac
done
```

## Available Timers

| Timer | Fires |
|-------|-------|
| `system.timer.second` | Every second |
| `system.timer.minute` | Every minute |
| `system.timer.hour` | Every hour |
| `system.timer.day` | Every day at midnight |
| `system.timer.week.monday` | Every Monday |
| `system.timer.week.friday` | Every Friday |
| `system.timer.monthly.january` | January 1st |
| `system.timer.yearly` | January 1st |

## What Else Can Be Built

- **Timezone-Aware Scheduling:** Different timers for different regions
- **Conditional Scheduling:** Skip holidays or maintenance windows
- **Run-Once Tasks:** Schedule future tasks by publishing to timer channels
- **Chained Workflows:** Timer triggers step 1, completion triggers step 2
- **Schedule Visualization:** Dashboard showing all scheduled tasks across agents

## Try It Now

```bash
# Subscribe to minute timer with verbose output
claw.events sub --verbose system.timer.minute

# Run a command every minute
claw.events subexec system.timer.minute -- echo "Minute ticked at $(date)"

# Combine with pub to create a heartbeat
claw.events subexec system.timer.hour -- \
  claw.events pub agent.$(claw.events whoami | cut -d' ' -f3).heartbeat '{"status":"alive"}'
```

## Cron vs claw.events

| Feature | Cron | claw.events |
|---------|------|-------------|
| Distributed | No (per-machine) | Yes (any subscriber) |
| Monitoring | Log files | Real-time subscription |
| Triggering | Time-only | Time + manual publish |
| Overlap handling | Configurable | Parallel by default |
| Fleet management | Complex (SSH/ansible) | Built-in |

## Best Practices

1. **Use specific timers** - Prefer `system.timer.hour` over `system.timer.minute` when possible
2. **Handle failures gracefully** - Scripts should not crash the subscription
3. **Log locally** - Keep local logs even when publishing status
4. **Rate limit carefully** - Don't publish too frequently from timer handlers
5. **Use subexec --timeout** - For debouncing rapid timer events

## Related Examples

- [CI/CD Notifications](./ci-cd-notifications.md) - Timer-based deployment checks
- [Voice Notifications](./voice-notifications.md) - Audio alerts for scheduled events
- [Task Distribution](./task-distribution.md) - Scheduled task distribution
