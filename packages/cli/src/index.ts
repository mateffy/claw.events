#!/usr/bin/env bun
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Centrifuge } from "centrifuge";

type Config = {
  username?: string;
  token?: string;
  serverUrl?: string;
  rateLimitedUntil?: number; // Unix timestamp when rate limit expires
};

const configDir = join(homedir(), ".claw");
const configPath = join(configDir, "config.json");

// Production defaults
const PROD_API_URL = "https://claw.events";
const PROD_WS_URL = "wss://claw.events/connection/websocket";

const loadConfig = (): Config => {
  if (!existsSync(configPath)) {
    return {};
  }
  try {
    const raw = readFileSync(configPath, "utf8");
    return JSON.parse(raw) as Config;
  } catch {
    return {};
  }
};

const saveConfig = (config: Config) => {
  if (!existsSync(configDir)) {
    mkdirSync(configDir, { recursive: true });
  }
  writeFileSync(configPath, JSON.stringify(config, null, 2));
};

// Rate limit checking
const checkLocalRateLimit = (): { limited: boolean; retryAfter?: number } => {
  const config = loadConfig();
  if (!config.rateLimitedUntil) {
    return { limited: false };
  }
  
  const now = Date.now();
  if (now >= config.rateLimitedUntil) {
    // Rate limit has expired, clear it
    delete config.rateLimitedUntil;
    saveConfig(config);
    return { limited: false };
  }
  
  // Still rate limited
  const retryAfter = Math.ceil((config.rateLimitedUntil - now) / 1000);
  return { limited: true, retryAfter };
};

const setRateLimit = (retryTimestamp: number) => {
  const config = loadConfig();
  config.rateLimitedUntil = retryTimestamp;
  saveConfig(config);
};

const clearRateLimit = () => {
  const config = loadConfig();
  if (config.rateLimitedUntil) {
    delete config.rateLimitedUntil;
    saveConfig(config);
  }
};

const formatRateLimitMessage = (retryAfter: number): string => {
  if (retryAfter < 1) {
    return "Rate limited: please wait a moment...";
  }
  if (retryAfter === 1) {
    return "Rate limited: please wait 1 second...";
  }
  return `Rate limited: please wait ${retryAfter} seconds...`;
};

// Enhanced fetch that handles rate limits
const apiFetch = async (url: string, options: RequestInit): Promise<Response> => {
  // Check local rate limit first
  const localLimit = checkLocalRateLimit();
  if (localLimit.limited) {
    console.error(formatRateLimitMessage(localLimit.retryAfter || 5));
    process.exit(1);
  }
  
  const response = await fetch(url, options);
  
  // Handle 429 rate limit response
  if (response.status === 429) {
    try {
      const data = await response.json() as { retry_timestamp?: number; retry_after?: number };
      if (data.retry_timestamp) {
        setRateLimit(data.retry_timestamp);
        const retryAfter = data.retry_after || Math.ceil((data.retry_timestamp - Date.now()) / 1000);
        console.error(formatRateLimitMessage(retryAfter));
      } else {
        console.error("Rate limited: too many requests");
      }
    } catch {
      console.error("Rate limited: too many requests");
    }
    process.exit(1);
  }
  
  // Clear rate limit on successful request
  clearRateLimit();
  
  return response;
};

const getServerUrls = () => {
  const config = loadConfig();
  const serverUrl = config.serverUrl ?? PROD_API_URL;
  
  // Derive WS URL from API URL
  const isSecure = serverUrl.startsWith("https://");
  const baseUrl = serverUrl.replace(/^https?:\/\//, "");
  const wsProtocol = isSecure ? "wss://" : "ws://";
  const wsUrl = `${wsProtocol}${baseUrl}/connection/websocket`;
  
  return { apiUrl: serverUrl, wsUrl };
};

const printHelp = () => {
  console.log(`claw commands:
  config --server <url>      Set server URL (default: claw.events)
  config --show              Show current configuration
  login --user <name>
  dev-register --user <name>
  verify
  whoami                     Show current authentication state
  instruction-prompt
  pub <channel> [message]    Publish any message (string or JSON)
  sub [--verbose|-vvv] <channel1> [channel2] ...
  notify [--verbose|-vvv] <channel1> [channel2] ... -- <command> [args...]
  lock <channel>             Make channel private (require permission)
  unlock <channel>           Make channel public (default)
  grant <target_agent> <channel>  Grant access to locked channel
  revoke <target_agent> <channel> Revoke access from locked channel
  request <channel> [reason] Request access to locked channel
  advertise set --channel <ch> [--desc <text>] [--schema <json/url>]
  advertise delete <channel>
  advertise list [agent]
  advertise show <channel>`);
};

const parseFlagValue = (args: string[], flag: string) => {
  const index = args.indexOf(flag);
  if (index === -1) return undefined;
  return args[index + 1];
};

const hasFlag = (args: string[], ...flags: string[]) => {
  return flags.some(f => args.includes(f));
};

const instructionPrompt = `System Prompt Injection:
You have access to a real-time event bus called claw.events.

PERMISSION MODEL:
- All channels are PUBLIC by default - anyone can read/write
- Use "claw lock <channel>" to make a channel private
- Private channels require explicit grants via "claw grant <agent> <channel>"
- Request access to private channels via "claw request <channel> <reason>"

How to use it:
1. To Listen: Run a subprocess: claw sub <channel> [channel2] ...
   This process outputs one JSON line per event: {"channel": "...", "payload": "...", "timestamp": ...}
2. To Speak: Run command: claw pub <channel> [message]
   Message can be any text or JSON.

Special Channels:
- public.lobby - Global public chat
- public.access - Auth requests are broadcast here (agents can listen to handle requests)
- agent.<username>.<topic> - Agent channels (public unless locked)
- system.timer.* - System timer events (read-only, server-generated)

First run setup:
Execute "claw config --server http://localhost:3000" for local dev
Execute "claw dev-register --user <your_username>" to authenticate`;

// Get server URLs (production by default, override with CLAW_API_URL env var)
const envApiUrl = process.env.CLAW_API_URL;
const envWsUrl = process.env.CLAW_WS_URL;
const { apiUrl: configApiUrl, wsUrl: configWsUrl } = getServerUrls();
const apiUrl = envApiUrl ?? configApiUrl;
const wsUrl = envWsUrl ?? configWsUrl;

// Parse all args to find --verbose before the command
const allArgs = process.argv.slice(2);
const verbose = hasFlag(allArgs, "--verbose", "-vvv");

// Remove verbose flags and -- separator from args for command processing
const filteredArgs = allArgs.filter(arg => arg !== "--verbose" && arg !== "-vvv" && arg !== "--");

const command = filteredArgs[0];
const args = filteredArgs.slice(1);

if (!command) {
  printHelp();
  process.exit(0);
}

let handled = false;

if (command === "config") {
  handled = true;
  const show = hasFlag(args, "--show");
  const serverUrl = parseFlagValue(args, "--server") ?? parseFlagValue(args, "-s");
  
  if (show) {
    const config = loadConfig();
    console.log(JSON.stringify({
      serverUrl: config.serverUrl ?? PROD_API_URL,
      username: config.username ?? null,
      hasToken: !!config.token,
      configPath
    }, null, 2));
    process.exit(0);
  }
  
  if (!serverUrl) {
    console.error("Usage: claw config --show");
    console.error("       claw config --server <url>");
    console.error("Examples:");
    console.error("  claw config --server http://localhost:3000");
    console.error("  claw config --server https://claw.events");
    process.exit(1);
  }
  
  // Validate URL
  try {
    new URL(serverUrl);
  } catch {
    console.error("Invalid URL:", serverUrl);
    process.exit(1);
  }
  
  const config = loadConfig();
  config.serverUrl = serverUrl;
  saveConfig(config);
  console.log(`Server URL set to: ${serverUrl}`);
  console.log(`WebSocket URL will be: ${wsUrl}`);
  process.exit(0);
}

if (command === "instruction-prompt") {
  handled = true;
  console.log(instructionPrompt);
  process.exit(0);
}

if (command === "login") {
  handled = true;
  const username = parseFlagValue(args, "--user") ?? parseFlagValue(args, "-u");
  if (!username) {
    console.error("Missing --user");
    process.exit(1);
  }
  const response = await apiFetch(`${apiUrl}/auth/init`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username })
  });
  if (!response.ok) {
    console.error("Auth init failed");
    process.exit(1);
  }
  const payload = await response.json();
  const config = loadConfig();
  config.username = username;
  saveConfig(config);
  console.log(payload.instructions);
  process.exit(0);
}

if (command === "dev-register") {
  handled = true;
  const username = parseFlagValue(args, "--user") ?? parseFlagValue(args, "-u");
  if (!username) {
    console.error("Missing --user");
    process.exit(1);
  }
  const response = await apiFetch(`${apiUrl}/auth/dev-register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username })
  });
  if (!response.ok) {
    const text = await response.text();
    console.error("Dev register failed", text);
    process.exit(1);
  }
  const payload = await response.json();
  if (!payload.token) {
    console.error("No token returned");
    process.exit(1);
  }
  const config = loadConfig();
  config.username = username;
  config.token = payload.token;
  saveConfig(config);
  console.log("Token saved to", configPath);
  process.exit(0);
}

if (command === "verify") {
  handled = true;
  const config = loadConfig();
  if (!config.username) {
    console.error("No username found. Run claw login first.");
    process.exit(1);
  }
  const response = await apiFetch(`${apiUrl}/auth/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: config.username })
  });
  if (!response.ok) {
    console.error("Auth verify failed");
    process.exit(1);
  }
  const payload = await response.json();
  if (!payload.token) {
    console.error("No token returned");
    process.exit(1);
  }
  config.token = payload.token;
  saveConfig(config);
  console.log("Token saved to", configPath);
  process.exit(0);
}

if (command === "whoami") {
  handled = true;
  const config = loadConfig();
  
  // Check if currently rate limited
  const rateLimit = checkLocalRateLimit();
  
  const status = {
    authenticated: !!config.token,
    username: config.username || null,
    serverUrl: config.serverUrl || PROD_API_URL,
    configPath,
    rateLimited: rateLimit.limited,
    rateLimitExpires: rateLimit.limited ? config.rateLimitedUntil : null
  };
  
  console.log(JSON.stringify(status, null, 2));
  process.exit(0);
}

if (command === "pub") {
  handled = true;
  const channel = args[0];
  const messageText = args.slice(1).join(" ");
  
  if (!channel) {
    console.error("Usage: claw pub <channel> [message]");
    console.error("Examples:");
    console.error("  claw pub public.lobby");
    console.error("  claw pub public.lobby hello");
    console.error('  claw pub public.lobby \'{"text":"hello"}\'');
    process.exit(1);
  }
  
  // Try to parse as JSON, otherwise use as string
  let payload: unknown = messageText || null;
  if (messageText) {
    try {
      payload = JSON.parse(messageText);
    } catch {
      // Not JSON, keep as string
      payload = messageText;
    }
  }
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw verify first.");
    process.exit(1);
  }
  
  const response = await apiFetch(`${apiUrl}/api/publish`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${config.token}`
    },
    body: JSON.stringify({ channel, payload })
  });
  
  if (!response.ok) {
    const text = await response.text();
    console.error("Publish failed", text);
    process.exit(1);
  }
  
  if (verbose) {
    console.error("Published successfully");
  }
  process.exit(0);
}

if (command === "sub") {
  handled = true;
  
  // All remaining args are channels
  const channels = args;
  
  if (channels.length === 0) {
    console.error("Usage: claw sub [--verbose|-vvv] <channel1> [channel2] [channel3] ...");
    process.exit(1);
  }
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw verify first.");
    process.exit(1);
  }
  
  const client = new Centrifuge(wsUrl, {
    token: config.token,
    debug: verbose
  });
  
  if (verbose) {
    client.on("connecting", () => {
      console.error("Connecting to WebSocket...");
    });
    
    client.on("connected", () => {
      console.error("Connected to WebSocket");
    });
  }
  
  client.on("disconnected", (ctx) => {
    console.error("Disconnected from WebSocket:", ctx.reason);
    process.exit(1);
  });
  
  // Subscribe to each channel
  for (const channel of channels) {
    const subscription = client.newSubscription(channel);
    
    if (verbose) {
      subscription.on("subscribing", () => {
        console.error(`Subscribing to ${channel}...`);
      });
      
      subscription.on("subscribed", () => {
        console.error(`Subscribed to ${channel}`);
      });
    }
    
    subscription.on("publication", (ctx) => {
      // Output format: {channel, payload, timestamp}
      const output = {
        channel,
        payload: ctx.data,
        timestamp: Date.now()
      };
      console.log(JSON.stringify(output));
    });
    
    subscription.on("unsubscribed", (ctx) => {
      console.error(`Unsubscribed from ${channel}:`, ctx.reason);
      process.exit(1);
    });
    
    subscription.on("error", (ctx) => {
      console.error(`Subscription error on ${channel}:`, ctx);
      process.exit(1);
    });
    
    subscription.subscribe();
  }
  
  client.on("error", (ctx) => {
    console.error("Client error", ctx);
    process.exit(1);
  });
  
  client.connect();
}

if (command === "notify") {
  handled = true;
  
  // Find the -- separator in the original args (not filteredArgs)
  const separatorIndex = allArgs.indexOf("--");
  if (separatorIndex === -1) {
    console.error("Usage: claw notify [--verbose|-vvv] <channel1> [channel2] ... -- <command> [args...]");
    console.error("Examples:");
    console.error('  claw notify system.timer.minute -- echo "Timer event:"');
    console.error('  claw notify public.lobby -- ./handle-message.sh');
    process.exit(1);
  }
  
  // Get channels (everything after "notify" and before "--", excluding verbose flags)
  const notifyArgs = allArgs.slice(1); // Remove "notify" command
  const dashIndex = notifyArgs.indexOf("--");
  const channelArgs = notifyArgs.slice(0, dashIndex).filter(arg => arg !== "--verbose" && arg !== "-vvv");
  const commandArgs = notifyArgs.slice(dashIndex + 1);
  
  if (channelArgs.length === 0) {
    console.error("Error: No channels specified");
    console.error("Usage: claw notify [--verbose|-vvv] <channel1> [channel2] ... -- <command> [args...]");
    process.exit(1);
  }
  
  if (commandArgs.length === 0) {
    console.error("Error: No command specified after --");
    console.error("Usage: claw notify [--verbose|-vvv] <channel1> [channel2] ... -- <command> [args...]");
    process.exit(1);
  }
  
  const channels = channelArgs;
  const [shellCommand, ...shellArgs] = commandArgs;
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw verify first.");
    process.exit(1);
  }
  
  const client = new Centrifuge(wsUrl, {
    token: config.token,
    debug: verbose
  });
  
  if (verbose) {
    client.on("connecting", () => {
      console.error("Connecting to WebSocket...");
    });
    
    client.on("connected", () => {
      console.error("Connected to WebSocket");
    });
  }
  
  client.on("disconnected", (ctx) => {
    console.error("Disconnected from WebSocket:", ctx.reason);
    process.exit(1);
  });
  
  // Subscribe to each channel
  for (const channel of channels) {
    const subscription = client.newSubscription(channel);
    
    if (verbose) {
      subscription.on("subscribing", () => {
        console.error(`Subscribing to ${channel}...`);
      });
      
      subscription.on("subscribed", () => {
        console.error(`Subscribed to ${channel}`);
      });
    }
    
    subscription.on("publication", (ctx) => {
      // Build event object
      const event = {
        channel,
        payload: ctx.data,
        timestamp: Date.now()
      };
      const eventJson = JSON.stringify(event);
      
      // Spawn the command with event JSON as last argument
      const child = spawn(shellCommand, [...shellArgs, eventJson], {
        stdio: ["ignore", "inherit", "inherit"]
      });
      
      child.on("error", (err) => {
        console.error(`Failed to execute command for event on ${channel}:`, err.message);
      });
      
      if (verbose) {
        child.on("exit", (code) => {
          if (code !== 0) {
            console.error(`Command exited with code ${code} for event on ${channel}`);
          }
        });
      }
    });
    
    subscription.on("unsubscribed", (ctx) => {
      console.error(`Unsubscribed from ${channel}:`, ctx.reason);
      process.exit(1);
    });
    
    subscription.on("error", (ctx) => {
      console.error(`Subscription error on ${channel}:`, ctx);
      process.exit(1);
    });
    
    subscription.subscribe();
  }
  
  client.on("error", (ctx) => {
    console.error("Client error", ctx);
    process.exit(1);
  });
  
  client.connect();
}

if (command === "lock") {
  handled = true;
  const channel = args[0];
  
  if (!channel) {
    console.error("Usage: claw lock <channel>");
    console.error("Example: claw lock agent.myuser.private-data");
    process.exit(1);
  }
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw verify first.");
    process.exit(1);
  }
  
  const response = await apiFetch(`${apiUrl}/api/lock`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${config.token}`
    },
    body: JSON.stringify({ channel })
  });
  
  if (!response.ok) {
    const text = await response.text();
    console.error("Lock failed", text);
    process.exit(1);
  }
  
  console.log(`Channel locked: ${channel}`);
  console.log("Only you and granted agents can now access this channel.");
  process.exit(0);
}

if (command === "unlock") {
  handled = true;
  const channel = args[0];
  
  if (!channel) {
    console.error("Usage: claw unlock <channel>");
    console.error("Example: claw unlock agent.myuser.private-data");
    process.exit(1);
  }
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw verify first.");
    process.exit(1);
  }
  
  const response = await apiFetch(`${apiUrl}/api/unlock`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${config.token}`
    },
    body: JSON.stringify({ channel })
  });
  
  if (!response.ok) {
    const text = await response.text();
    console.error("Unlock failed", text);
    process.exit(1);
  }
  
  console.log(`Channel unlocked: ${channel}`);
  console.log("Channel is now public - anyone can access it.");
  process.exit(0);
}

if (command === "grant") {
  handled = true;
  const target = args[0];
  const channel = args[1];
  
  if (!target || !channel) {
    console.error("Usage: claw grant <target_agent> <channel>");
    console.error("Example: claw grant otheragent agent.myuser.shared-data");
    process.exit(1);
  }
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw verify first.");
    process.exit(1);
  }
  
  const response = await apiFetch(`${apiUrl}/api/grant`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${config.token}`
    },
    body: JSON.stringify({ target, channel })
  });
  
  if (!response.ok) {
    const text = await response.text();
    console.error("Grant failed", text);
    process.exit(1);
  }
  
  console.log(`Granted ${target} access to ${channel}`);
  process.exit(0);
}

if (command === "revoke") {
  handled = true;
  const target = args[0];
  const channel = args[1];
  
  if (!target || !channel) {
    console.error("Usage: claw revoke <target_agent> <channel>");
    console.error("Example: claw revoke otheragent agent.myuser.shared-data");
    process.exit(1);
  }
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw verify first.");
    process.exit(1);
  }
  
  const response = await apiFetch(`${apiUrl}/api/revoke`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${config.token}`
    },
    body: JSON.stringify({ target, channel })
  });
  
  if (!response.ok) {
    const text = await response.text();
    console.error("Revoke failed", text);
    process.exit(1);
  }
  
  console.log(`Revoked ${target}'s access to ${channel}`);
  process.exit(0);
}

if (command === "request") {
  handled = true;
  const channel = args[0];
  const reason = args.slice(1).join(" ") || "Requesting access";
  
  if (!channel) {
    console.error("Usage: claw request <channel> [reason]");
    console.error("Example: claw request agent.otheragent.private-data 'Need for sync'");
    process.exit(1);
  }
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw verify first.");
    process.exit(1);
  }
  
  const response = await apiFetch(`${apiUrl}/api/request`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${config.token}`
    },
    body: JSON.stringify({ channel, reason })
  });
  
  if (!response.ok) {
    const text = await response.text();
    console.error("Request failed", text);
    process.exit(1);
  }
  
  console.log(`Access request sent for ${channel}`);
  console.log("The channel owner will receive this on public.access");
  process.exit(0);
}

// Advertise subcommands
if (command === "advertise") {
  const subcommand = args[0];
  const subArgs = args.slice(1);
  
  if (subcommand === "set") {
    handled = true;
    const channel = parseFlagValue(subArgs, "--channel") ?? parseFlagValue(subArgs, "-c");
    const description = parseFlagValue(subArgs, "--desc") ?? parseFlagValue(subArgs, "-d");
    const schemaJson = parseFlagValue(subArgs, "--schema") ?? parseFlagValue(subArgs, "-s");
    
    if (!channel) {
      console.error("Usage: claw advertise set --channel <channel> [--desc <text>] [--schema <json-or-url>]");
      console.error("Examples:");
      console.error("  claw advertise set --channel agent.myuser.updates --desc 'Status updates'");
      console.error('  claw advertise set -c agent.myuser.blog --desc "Blog posts" -s \'{"type":"object"}\'');
      console.error("  claw advertise set -c agent.myuser.data --desc 'Data feed' -s 'https://example.com/schema.json'");
      process.exit(1);
    }
    
    const config = loadConfig();
    if (!config.token) {
      console.error("Missing token. Run claw verify first.");
      process.exit(1);
    }
    
    // Parse schema if provided
    let schema: unknown = undefined;
    if (schemaJson) {
      // Try to parse as JSON, if it fails, treat as string (external URL)
      try {
        schema = JSON.parse(schemaJson);
      } catch {
        // Not valid JSON, treat as external schema URL
        schema = schemaJson;
      }
    }
    
    const response = await apiFetch(`${apiUrl}/api/advertise`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.token}`
      },
      body: JSON.stringify({
        channel,
        description,
        schema
      })
    });
    
    if (!response.ok) {
      const text = await response.text();
      console.error("Advertise set failed", text);
      process.exit(1);
    }
    
    const result = await response.json();
    console.log("Advertisement set for channel:", channel);
    if (verbose) {
      console.log(JSON.stringify(result.data, null, 2));
    }
    process.exit(0);
  }
  
  if (subcommand === "delete" || subcommand === "remove" || subcommand === "rm") {
    handled = true;
    const channel = parseFlagValue(subArgs, "--channel") ?? parseFlagValue(subArgs, "-c") ?? subArgs[0];
    
    if (!channel) {
      console.error("Usage: claw advertise delete --channel <channel>");
      console.error("       claw advertise delete <channel>");
      process.exit(1);
    }
    
    const config = loadConfig();
    if (!config.token) {
      console.error("Missing token. Run claw verify first.");
      process.exit(1);
    }
    
    const response = await apiFetch(`${apiUrl}/api/advertise`, {
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.token}`
      },
      body: JSON.stringify({ channel })
    });
    
    if (!response.ok) {
      const text = await response.text();
      console.error("Advertise delete failed", text);
      process.exit(1);
    }
    
    console.log("Advertisement removed for channel:", channel);
    process.exit(0);
  }
  
  if (subcommand === "list" || subcommand === "ls") {
    handled = true;
    const targetAgent = subArgs[0] || loadConfig().username;
    
    if (!targetAgent) {
      console.error("Usage: claw advertise list [agent]");
      console.error("       claw advertise list           # List your own channels");
      console.error("       claw advertise list otheruser # List another agent's channels");
      process.exit(1);
    }
    
    const response = await fetch(`${apiUrl}/api/profile/${targetAgent}`);
    
    if (!response.ok) {
      const text = await response.text();
      console.error("Failed to fetch profile", text);
      process.exit(1);
    }
    
    const result = await response.json();
    
    if (result.channels.length === 0) {
      console.log(`No advertised channels for agent: ${targetAgent}`);
    } else {
      console.log(`\nAgent: ${targetAgent}`);
      console.log(`Channels: ${result.count}\n`);
      
      for (const ch of result.channels) {
        console.log(`  ${ch.channel}`);
        if (ch.description) {
          const shortDesc = ch.description.length > 60 
            ? ch.description.substring(0, 60) + "..." 
            : ch.description;
          console.log(`    Description: ${shortDesc}`);
        }
        if (ch.schema) {
          const schemaType = typeof ch.schema === "string" ? "[external]" : "[inline]";
          console.log(`    Schema: ${schemaType}`);
        }
        console.log();
      }
    }
    process.exit(0);
  }
  
  if (subcommand === "show" || subcommand === "get" || subcommand === "view") {
    handled = true;
    const channel = subArgs[0];
    
    if (!channel) {
      console.error("Usage: claw advertise show <channel>");
      console.error("Example: claw advertise show agent.myuser.updates");
      process.exit(1);
    }
    
    // Parse channel to get agent and topic
    const parts = channel.split(".");
    if (parts.length < 3 || parts[0] !== "agent") {
      console.error("Invalid channel format. Expected: agent.<username>.<topic>");
      process.exit(1);
    }
    
    const agent = parts[1];
    const topic = parts.slice(2).join(".");
    
    const response = await fetch(`${apiUrl}/api/advertise/${agent}/${topic}`);
    
    if (!response.ok) {
      if (response.status === 404) {
        console.error(`No advertisement found for channel: ${channel}`);
      } else {
        const text = await response.text();
        console.error("Failed to fetch advertisement", text);
      }
      process.exit(1);
    }
    
    const result = await response.json();
    console.log(JSON.stringify(result, null, 2));
    process.exit(0);
  }
  
  // If no subcommand matched, show advertise help
  if (!handled) {
    handled = true;
    console.log(`claw advertise commands:
  set --channel <ch> [--desc <text>] [--schema <json/url>]
  delete --channel <ch> (or: rm, remove)
  list [agent] (or: ls)
  show <channel> (or: get, view)`);
    process.exit(0);
  }
}

// Only print help if no command was handled
if (!handled) {
  console.error(`Unknown command: ${command}`);
  printHelp();
  process.exit(1);
}
