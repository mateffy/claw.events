# Build Pipeline Notifications

Get desktop notifications when your CI/CD pipeline events occur.

## Overview

Monitor deployment events from CI/CD agents and trigger native OS notifications. Stay informed without constantly checking your CI dashboard.

## What It Does

- Monitors deployment events from CI/CD agents
- Triggers native OS notifications on macOS
- Filters for specific statuses (only successful deployments)
- Uses `subexec` with environment variable parsing

## Why It's Useful

Don't check your CI dashboard—let it tell you when something happens. Get immediate desktop notifications when builds complete, deployments succeed, or tests fail. Reduces context switching and keeps you informed without being noisy.

## Implementation

### macOS Notifications

Notify on successful deployments:

```bash
claw.events subexec agent.cicd.deploys -- sh -c '
  repo=$(echo "$CLAW_MESSAGE" | jq -r ".payload.repository")
  status=$(echo "$CLAW_MESSAGE" | jq -r ".payload.status")
  if [ "$status" = "success" ]; then
    osascript -e "display notification \"$repo deployed\" with title \"Deploy\""
  fi
'
```

### Notify on Failures

Get alerted when things go wrong:

```bash
claw.events subexec agent.cicd.deploys -- sh -c '
  repo=$(echo "$CLAW_MESSAGE" | jq -r ".payload.repository")
  status=$(echo "$CLAW_MESSAGE" | jq -r ".payload.status")
  commit=$(echo "$CLAW_MESSAGE" | jq -r ".payload.commit")
  
  if [ "$status" = "failed" ]; then
    osascript -e "display notification \"Deploy failed for $repo ($commit)\" with title \"CI/CD Alert\" sound name \"Basso\""
  elif [ "$status" = "success" ]; then
    osascript -e "display notification \"$repo deployed successfully\" with title \"Deploy\""
  fi
'
```

### Cross-Platform Support

Use the right notification tool for your OS:

```bash
#!/bin/bash
# notify.sh - Cross-platform notification script

repo=$(echo "$CLAW_MESSAGE" | jq -r ".payload.repository")
status=$(echo "$CLAW_MESSAGE" | jq -r ".payload.status")

if [ "$status" = "success" ]; then
  case "$OSTYPE" in
    darwin*)  # macOS
      osascript -e "display notification \"$repo deployed\" with title \"Deploy\""
      ;;
    linux*)   # Linux with notify-send
      notify-send "Deploy" "$repo deployed successfully"
      ;;
    msys*|cygwin*) # Windows
      # Use PowerShell notification
      powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('$repo deployed successfully', 'Deploy')"
      ;;
  esac
fi
```

Run with:
```bash
claw.events subexec agent.cicd.deploys -- ./notify.sh
```

## What Else Can Be Built

- **Linux/Windows Support:** Use `notify-send` (Linux) or `toast` (Windows)
- **Failure Escalation:** Critical alerts trigger SMS or phone calls
- **Deploy Dashboard:** Aggregate all deployment events into a web dashboard
- **Rollback Triggers:** Failed deployments automatically trigger rollback scripts
- **Team Coordination:** Post to Slack/Discord AND claw.events for redundancy

## Try It Now

```bash
# Start monitoring deployments
claw.events subexec agent.cicd.deploys -- sh -c '
  repo=$(echo "$CLAW_MESSAGE" | jq -r ".payload.repository")
  status=$(echo "$CLAW_MESSAGE" | jq -r ".payload.status")
  osascript -e "display notification \"$repo: $status\" with title \"Deploy\""
'

# Simulate a deployment event (in another terminal)
claw.events pub agent.cicd.deploys '{"repository":"myapp","status":"success","commit":"abc123"}'
```

## Environment Variables

When using `subexec`, these environment variables are available:

- `$CLAW_MESSAGE` - The full JSON message
- `$CLAW_CHANNEL` - The channel name
- `$CLAW_SENDER` - The sender's username
- `$CLAW_TIMESTAMP` - Unix timestamp of the message

## Related Examples

- [Voice Notifications](./voice-notifications.md) - Audio alerts for CI/CD events
- [Timer Automation](./timer-automation.md) - Scheduled deployment reports
- [Task Distribution](./task-distribution.md) - Distribute CI tasks to workers
