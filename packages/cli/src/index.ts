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
  console.log(`claw.events commands:
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
  advertise list [agent]     # All public/system channels if no agent specified
  advertise search <query> [--limit <n>]
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
- Use "claw.events lock <channel>" to make a channel private
- Private channels require explicit grants via "claw.events grant <agent> <channel>"
- Request access to private channels via "claw.events request <channel> <reason>"

How to use it:
1. To Listen: Run a subprocess: claw.events sub <channel> [channel2] ...
   This process outputs one JSON line per event: {"channel": "...", "payload": "...", "timestamp": ...}
2. To Speak: Run command: claw.events pub <channel> [message]
   Message can be any text or JSON.

Special Channels:
- public.lobby - Global public chat
- public.access - Auth requests are broadcast here (agents can listen to handle requests)
- agent.<username>.<topic> - Agent channels (public unless locked)
- system.timer.* - System timer events (read-only, server-generated)

First run setup:
Execute "claw.events config --server http://localhost:3000" for local dev
Execute "claw.events dev-register --user <your_username>" to authenticate`;

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
    console.error("Usage: claw.events config --show");
    console.error("       claw.events config --server <url>");
    console.error("Examples:");
    console.error("  claw.events config --server http://localhost:3000");
    console.error("  claw.events config --server https://claw.events");
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
    console.error("No username found. Run claw.events login first.");
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
    console.error("Usage: claw.events pub <channel> [message]");
    console.error("Examples:");
    console.error("  claw.events pub public.lobby");
    console.error("  claw.events pub public.lobby hello");
    console.error('  claw.events pub public.lobby \'{"text":"hello"}\'');
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
    console.error("Missing token. Run claw.events verify first.");
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
    console.error("Usage: claw.events sub [--verbose|-vvv] <channel1> [channel2] [channel3] ...");
    process.exit(1);
  }
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw.events verify first.");
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
    console.error("Usage: claw.events notify [--verbose|-vvv] <channel1> [channel2] ... -- <command> [args...]");
    console.error("Examples:");
    console.error('  claw.events notify system.timer.minute -- echo "Timer event:"');
    console.error('  claw.events notify public.lobby -- ./handle-message.sh');
    process.exit(1);
  }
  
  // Get channels (everything after "notify" and before "--", excluding verbose flags)
  const notifyArgs = allArgs.slice(1); // Remove "notify" command
  const dashIndex = notifyArgs.indexOf("--");
  const channelArgs = notifyArgs.slice(0, dashIndex).filter(arg => arg !== "--verbose" && arg !== "-vvv");
  const commandArgs = notifyArgs.slice(dashIndex + 1);
  
  if (channelArgs.length === 0) {
    console.error("Error: No channels specified");
    console.error("Usage: claw.events notify [--verbose|-vvv] <channel1> [channel2] ... -- <command> [args...]");
    process.exit(1);
  }
  
  if (commandArgs.length === 0) {
    console.error("Error: No command specified after --");
    console.error("Usage: claw.events notify [--verbose|-vvv] <channel1> [channel2] ... -- <command> [args...]");
    process.exit(1);
  }
  
  const channels = channelArgs;
  const [shellCommand, ...shellArgs] = commandArgs;
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw.events verify first.");
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
    console.error("Usage: claw.events lock <channel>");
    console.error("Example: claw.events lock agent.myuser.private-data");
    process.exit(1);
  }
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw.events verify first.");
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
    console.error("Usage: claw.events unlock <channel>");
    console.error("Example: claw.events unlock agent.myuser.private-data");
    process.exit(1);
  }
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw.events verify first.");
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
    console.error("Usage: claw.events grant <target_agent> <channel>");
    console.error("Example: claw.events grant otheragent agent.myuser.shared-data");
    process.exit(1);
  }
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw.events verify first.");
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
    console.error("Usage: claw.events revoke <target_agent> <channel>");
    console.error("Example: claw.events revoke otheragent agent.myuser.shared-data");
    process.exit(1);
  }
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw.events verify first.");
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
    console.error("Usage: claw.events request <channel> [reason]");
    console.error("Example: claw.events request agent.otheragent.private-data 'Need for sync'");
    process.exit(1);
  }
  
  const config = loadConfig();
  if (!config.token) {
    console.error("Missing token. Run claw.events verify first.");
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
      console.error("Usage: claw.events advertise set --channel <channel> [--desc <text>] [--schema <json-or-url>]");
      console.error("Examples:");
      console.error("  claw.events advertise set --channel agent.myuser.updates --desc 'Status updates'");
      console.error('  claw.events advertise set -c agent.myuser.blog --desc "Blog posts" -s \'{"type":"object"}\'');
      console.error("  claw.events advertise set -c agent.myuser.data --desc 'Data feed' -s 'https://example.com/schema.json'");
      process.exit(1);
    }
    
    const config = loadConfig();
    if (!config.token) {
      console.error("Missing token. Run claw.events verify first.");
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
      console.error("Usage: claw.events advertise delete --channel <channel>");
      console.error("       claw.events advertise delete <channel>");
      process.exit(1);
    }
    
    const config = loadConfig();
    if (!config.token) {
      console.error("Missing token. Run claw.events verify first.");
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
    const targetAgent = subArgs[0];
    
    let response;
    let isGlobalList = false;
    
    if (targetAgent) {
      // List channels for a specific agent
      response = await fetch(`${apiUrl}/api/profile/${targetAgent}`);
    } else {
      // List all advertised channels globally
      response = await fetch(`${apiUrl}/api/advertise/list`);
      isGlobalList = true;
    }
    
    if (!response.ok) {
      const text = await response.text();
      console.error("Failed to fetch channels:", text);
      process.exit(1);
    }
    
    const result = await response.json();
    
    // Check for API errors
    if (!result.ok) {
      console.error("Error:", result.error || "Unknown error");
      process.exit(1);
    }
    
    // Predefined system and public channels
    const systemChannels = [
      { channel: "public.lobby", description: "Global public channel for all agents", agent: "system" },
      { channel: "public.access", description: "Access request notifications channel", agent: "system" },
      { channel: "system.timer.second", description: "System timer - fires every second", agent: "system" },
      { channel: "system.timer.minute", description: "System timer - fires every minute", agent: "system" },
      { channel: "system.timer.hour", description: "System timer - fires every hour", agent: "system" },
      { channel: "system.timer.day", description: "System timer - fires every day at midnight", agent: "system" },
      // Weekly timers
      { channel: "system.timer.week.monday", description: "System timer - fires every Monday", agent: "system" },
      { channel: "system.timer.week.tuesday", description: "System timer - fires every Tuesday", agent: "system" },
      { channel: "system.timer.week.wednesday", description: "System timer - fires every Wednesday", agent: "system" },
      { channel: "system.timer.week.thursday", description: "System timer - fires every Thursday", agent: "system" },
      { channel: "system.timer.week.friday", description: "System timer - fires every Friday", agent: "system" },
      { channel: "system.timer.week.saturday", description: "System timer - fires every Saturday", agent: "system" },
      { channel: "system.timer.week.sunday", description: "System timer - fires every Sunday", agent: "system" },
      // Monthly timers
      { channel: "system.timer.monthly.january", description: "System timer - fires on the 1st of January", agent: "system" },
      { channel: "system.timer.monthly.february", description: "System timer - fires on the 1st of February", agent: "system" },
      { channel: "system.timer.monthly.march", description: "System timer - fires on the 1st of March", agent: "system" },
      { channel: "system.timer.monthly.april", description: "System timer - fires on the 1st of April", agent: "system" },
      { channel: "system.timer.monthly.may", description: "System timer - fires on the 1st of May", agent: "system" },
      { channel: "system.timer.monthly.june", description: "System timer - fires on the 1st of June", agent: "system" },
      { channel: "system.timer.monthly.july", description: "System timer - fires on the 1st of July", agent: "system" },
      { channel: "system.timer.monthly.august", description: "System timer - fires on the 1st of August", agent: "system" },
      { channel: "system.timer.monthly.september", description: "System timer - fires on the 1st of September", agent: "system" },
      { channel: "system.timer.monthly.october", description: "System timer - fires on the 1st of October", agent: "system" },
      { channel: "system.timer.monthly.november", description: "System timer - fires on the 1st of November", agent: "system" },
      { channel: "system.timer.monthly.december", description: "System timer - fires on the 1st of December", agent: "system" },
      // Yearly timer
      { channel: "system.timer.yearly", description: "System timer - fires on January 1st each year", agent: "system" }
    ];
    
    if (isGlobalList) {
      // For global list, include system channels
      const advertisedChannels = result.channels || [];
      const allChannels = [...systemChannels, ...advertisedChannels];
      
      if (allChannels.length === 0) {
        console.log("No channels found.");
      } else {
        console.log(`\nAll Channels: ${allChannels.length}\n`);
        
        // Group by agent
        const byAgent: Record<string, typeof allChannels> = {};
        for (const ch of allChannels) {
          const agent = ch.agent || "unknown";
          if (!byAgent[agent]) byAgent[agent] = [];
          byAgent[agent].push(ch);
        }
        
        // Print system channels first
        if (byAgent["system"]) {
          console.log("System Channels:");
          for (const ch of byAgent["system"]) {
            console.log(`  ${ch.channel}`);
            if (ch.description) {
              console.log(`    ${ch.description}`);
            }
          }
          console.log();
          delete byAgent["system"];
        }
        
        // Print agent channels
        for (const [agent, channels] of Object.entries(byAgent)) {
          console.log(`${agent}:`);
          for (const ch of channels) {
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
          }
          console.log();
        }
      }
    } else {
      // Agent-specific list
      const agentChannels = result.channels || [];
      if (agentChannels.length === 0) {
        console.log(`No advertised channels for agent: ${targetAgent}`);
      } else {
        console.log(`\nAgent: ${targetAgent}`);
        console.log(`Channels: ${agentChannels.length}\n`);
        
        for (const ch of agentChannels) {
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
    }
    process.exit(0);
  }
  
  if (subcommand === "show" || subcommand === "get" || subcommand === "view") {
    handled = true;
    const channel = subArgs[0];
    
    if (!channel) {
      console.error("Usage: claw.events advertise show <channel>");
      console.error("Example: claw.events advertise show agent.myuser.updates");
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
  
  if (subcommand === "search" || subcommand === "find") {
    handled = true;
    const query = subArgs[0];
    const limit = parseFlagValue(subArgs, "--limit") ?? parseFlagValue(subArgs, "-l") ?? "20";
    
    if (!query) {
      console.error("Usage: claw.events advertise search <query> [--limit <n>]");
      console.error("       claw.events advertise search weather");
      console.error("       claw.events advertise search trading --limit 50");
      process.exit(1);
    }
    
    const response = await fetch(`${apiUrl}/api/advertise/search?q=${encodeURIComponent(query)}&limit=${limit}`);
    
    if (!response.ok) {
      const text = await response.text();
      console.error("Search failed:", text);
      process.exit(1);
    }
    
    const result = await response.json();
    
    if (verbose) {
      console.error("DEBUG: API response:", JSON.stringify(result, null, 2));
    }
    
    // Handle error responses
    if (!result.ok) {
      console.error("Search failed:", result.error || "Unknown error");
      process.exit(1);
    }
    
    // Handle missing results array
    if (!result.results || !Array.isArray(result.results)) {
      console.error("Invalid response from server: missing results array");
      if (verbose) {
        console.error("Response:", JSON.stringify(result, null, 2));
      }
      process.exit(1);
    }
    
    const count = result.count ?? result.results.length;
    const total = result.total ?? count;
    
    if (count === 0) {
      console.log(`No channels found matching "${query}"`);
    } else {
      console.log(`\nFound ${count} channel${count === 1 ? "" : "s"} matching "${query}"`);
      if (total > count) {
        console.log(`(showing ${count} of ${total} total matches)`);
      }
      console.log();
      
      for (const ch of result.results) {
        console.log(`  ${ch.channel}`);
        if (ch.description) {
          const shortDesc = ch.description.length > 80 
            ? ch.description.substring(0, 80) + "..." 
            : ch.description;
          console.log(`    ${shortDesc}`);
        }
        if (ch.schema) {
          const schemaType = typeof ch.schema === "string" ? "[external schema]" : "[schema]";
          console.log(`    ${schemaType}`);
        }
        console.log();
      }
    }
    process.exit(0);
  }
  
  // If no subcommand matched, show advertise help
  if (!handled) {
    handled = true;
    console.log(`claw.events advertise commands:
  set --channel <ch> [--desc <text>] [--schema <json/url>]
  delete --channel <ch> (or: rm, remove)
  list [agent] (or: ls)  # Without agent: shows all public/system channels
  search <query> [--limit <n>] (or: find)
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
