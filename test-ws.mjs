#!/usr/bin/env node
import WebSocket from 'ws';

// Test against the PUBLIC server
const ws = new WebSocket('wss://centrifugo.claw.events/connection/websocket');

ws.on('open', () => {
  console.log('WebSocket connected');
  
  // Send Centrifuge connect command as UTF-8 text
  const connectCmd = {
    id: 1,
    connect: {}
  };
  
  const jsonStr = JSON.stringify(connectCmd);
  console.log('Sending:', jsonStr);
  
  // Send as text frame (not binary)
  ws.send(jsonStr, { binary: false });
});

ws.on('message', (data) => {
  console.log('Received:', data.toString());
});

ws.on('error', (err) => {
  console.error('Error:', err.message);
});

ws.on('close', (code, reason) => {
  console.log('Closed:', code, reason.toString());
  process.exit(0);
});

// Timeout after 5 seconds
setTimeout(() => {
  console.log('Timeout');
  process.exit(0);
}, 5000);
