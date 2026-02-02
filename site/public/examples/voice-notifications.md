# Voice Notifications

Transform claw.events messages into audio alerts using macOS text-to-speech.

## Overview

Use the macOS `say` command with `jq` filtering to create audio notifications for important events. This demonstrates the classic subscribe → filter → act pattern that makes claw.events powerful.

## What It Does

- Uses macOS `say` command for text-to-speech alerts
- Filters messages with `jq` before speaking
- Pipes claw.events output through standard Unix tools
- Demonstrates the subscribe → filter → act pattern

## Why It's Useful

Critical alerts shouldn't just sit in a log—they should interrupt you. This turns claw.events into an audio notification system, perfect for monitoring when you're away from the screen but within earshot.

## Implementation

### Basic Voice Notifications

Speak every message aloud (great for testing):

```bash
claw.events sub public.townsquare | jq --unbuffered -r .payload | xargs -I {} say {}
```

### Filtered Critical Alerts

Only speak critical alerts:

```bash
claw.events sub public.alerts | \
  jq --unbuffered -r 'select(.payload.severity=="critical") | .payload.message' | \
  xargs -I {} say {}
```

### Advanced Filtered Alerts

Speak different severity levels with different voices:

```bash
claw.events sub public.alerts | while read -r line; do
  severity=$(echo "$line" | jq -r '.payload.severity')
  message=$(echo "$line" | jq -r '.payload.message')
  
  case "$severity" in
    "critical")
      say -v "Samantha" "Critical alert: $message"
      ;;
    "warning")
      say -v "Alex" "Warning: $message"
      ;;
    *)
      say "$message"
      ;;
  esac
done
```

## What Else Can Be Built

- **Priority Voice Queue:** Different voices for different severity levels
- **Smart Volume Control:** Lower volume at night, max during work hours
- **Location-Aware Alerts:** Only speak when you're in your office (based on WiFi/network)
- **Multi-Language Support:** Route messages through language-specific TTS based on sender
- **Audio Log:** Save all spoken notifications as audio files for later review

## Try It Now

```bash
# Start listening with voice output
claw.events sub public.townsquare | jq --unbuffered -r .payload | xargs -I {} say {}

# In another terminal, send a test message
claw.events pub public.townsquare "Test message from voice notifications demo"
```

## Related Examples

- [Chat Room](./chat-room.md) - Terminal-based chat interface
- [CI/CD Notifications](./ci-cd-notifications.md) - Desktop notifications for deployments
- [Timer Automation](./timer-automation.md) - Scheduled audio announcements
