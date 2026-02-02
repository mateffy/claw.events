/**
 * Shared test utilities for claw.events
 * 
 * This module provides common utilities for all test files to ensure
 * consistent test setup, dynamic port allocation, and proper cleanup.
 */

import type { Server } from "bun";
import { createClient, type RedisClientType } from "redis";

// Port range for test servers to avoid conflicts
const BASE_PORT = 3100;
const MAX_PORT = 3200;

/**
 * Check if a port is available
 */
const isPortAvailable = (port: number): boolean => {
  try {
    const server = Bun.serve({
      port,
      fetch: () => new Response("test"),
    });
    server.stop();
    return true;
  } catch {
    return false;
  }
};

/**
 * Get the next available port for a test server
 */
export const getNextPort = (): number => {
  for (let port = BASE_PORT; port < MAX_PORT; port++) {
    if (isPortAvailable(port)) {
      return port;
    }
  }
  throw new Error(`No available ports found between ${BASE_PORT} and ${MAX_PORT}`);
};

/**
 * Test configuration interface
 */
export interface TestConfig {
  port: number;
  apiUrl: string;
  jwtSecret: string;
  redisUrl: string;
  centrifugoApiUrl: string;
  centrifugoApiKey: string;
  moltbookApiBase: string;
  moltbookApiKey: string;
  devMode: string;
}

/**
 * Create a test configuration with dynamic port
 */
export const createTestConfig = (): TestConfig => {
  const port = getNextPort();
  return {
    port,
    apiUrl: `http://localhost:${port}`,
    jwtSecret: "test-jwt-secret-for-testing-only",
    redisUrl: process.env.REDIS_URL || "redis://localhost:6380",
    centrifugoApiUrl: process.env.CENTRIFUGO_API_URL || "http://localhost:8000/api",
    centrifugoApiKey: process.env.CENTRIFUGO_API_KEY || "test-api-key-for-testing",
    moltbookApiBase: process.env.MOLTBOOK_API_BASE || "http://localhost:9000/api/v1",
    moltbookApiKey: process.env.MOLTBOOK_API_KEY || "test-moltbook-key",
    devMode: "true",
  };
};

/**
 * Test context interface
 */
export interface TestContext {
  config: TestConfig;
  server: Server | null;
  redis: RedisClientType | null;
  moltbookMockServer: Server | null;
  originalEnv: Record<string, string | undefined>;
  expectedSignatures: Map<string, string>;
}

/**
 * Create a test context with all necessary setup
 */
export const createTestContext = async (): Promise<TestContext> => {
  const config = createTestConfig();
  
  // Save original environment
  const originalEnv = { ...process.env };
  
  // Set test environment
  process.env.PORT = String(config.port);
  process.env.JWT_SECRET = config.jwtSecret;
  process.env.REDIS_URL = config.redisUrl;
  process.env.CENTRIFUGO_API_URL = config.centrifugoApiUrl;
  process.env.CENTRIFUGO_API_KEY = config.centrifugoApiKey;
  process.env.MOLTBOOK_API_BASE = config.moltbookApiBase;
  process.env.MOLTBOOK_API_KEY = config.moltbookApiKey;
  process.env.CLAW_DEV_MODE = config.devMode;
  
  // Connect to Redis
  const redis = createClient({ url: config.redisUrl });
  await redis.connect();
  
  return {
    config,
    server: null,
    redis,
    moltbookMockServer: null,
    originalEnv,
    expectedSignatures: new Map(),
  };
};

/**
 * Start the mock MoltBook API server for testing auth flows
 */
export const startMoltbookMockServer = async (context: TestContext, port: number = 9000): Promise<void> => {
  context.moltbookMockServer = Bun.serve({
    port,
    fetch(req) {
      const url = new URL(req.url);

      // Handle agents/profile endpoint
      if (url.pathname === "/api/v1/agents/profile") {
        const name = url.searchParams.get("name");
        if (!name) {
          return new Response(
            JSON.stringify({ success: false, error: "Name required" }),
            { status: 400, headers: { "Content-Type": "application/json" } }
          );
        }

        // Check if we have an expected signature for this user
        const expectedSig = context.expectedSignatures.get(name);

        // Handle special error cases
        if (expectedSig === "__ERROR_500__") {
          return new Response(
            JSON.stringify({ error: "Internal Server Error" }),
            { status: 500, headers: { "Content-Type": "application/json" } }
          );
        }

        // If no expected signature set, return 404 (user not found)
        if (expectedSig === undefined) {
          return new Response(
            JSON.stringify({ error: "Agent not found" }),
            { status: 404, headers: { "Content-Type": "application/json" } }
          );
        }

        // Return profile with expected signature in description
        return new Response(
          JSON.stringify({
            success: true,
            agent: {
              name,
              description: `Test profile with ${expectedSig}`,
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }

      return new Response("Not found", { status: 404 });
    },
  });
  
  // Wait a moment for server to be ready
  await new Promise((resolve) => setTimeout(resolve, 100));
};

/**
 * Start the API server for testing
 */
export const startTestServer = async (context: TestContext): Promise<void> => {
  // Import index.ts - it will auto-start a server on the port set in process.env.PORT
  const { default: app } = await import("./index.ts");
  
  // Wait for the auto-started server to be ready
  await new Promise((resolve) => setTimeout(resolve, 500));
  
  // The server is auto-started by index.ts when imported, so we don't need to start another
  // Just store a reference so cleanup works
  context.server = {
    stop: () => {
      // The server is managed by index.ts, we can't really stop it from here
      // But we need to satisfy the interface
      console.log("[test-utils] Note: Server auto-started by index.ts continues running");
    }
  } as unknown as Server;
};

/**
 * Cleanup test context
 */
export const cleanupTestContext = async (context: TestContext): Promise<void> => {
  if (context.server) {
    context.server.stop();
    context.server = null;
  }
  
  if (context.moltbookMockServer) {
    context.moltbookMockServer.stop();
    context.moltbookMockServer = null;
  }
  
  if (context.redis) {
    await context.redis.quit();
    context.redis = null;
  }
  
  // Restore original environment
  process.env = context.originalEnv;
};

/**
 * Create a valid JWT token for testing
 */
export const createTestToken = async (
  username: string,
  jwtSecret: string,
  options?: { expired?: boolean }
): Promise<string> => {
  const { SignJWT } = await import("jose");
  const jwtKey = new TextEncoder().encode(jwtSecret);
  const jwt = new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(username)
    .setIssuedAt();
  
  if (options?.expired) {
    jwt.setExpirationTime("-1h");
  } else {
    jwt.setExpirationTime("7d");
  }
  
  return jwt.sign(jwtKey);
};

/**
 * Clear all test data from Redis
 */
export const clearTestData = async (redis: RedisClientType): Promise<void> => {
  const keys = await redis.keys("*");
  const testKeys = keys.filter((k) =>
    k.startsWith("authsig:") ||
    k.startsWith("claim:") ||
    k.startsWith("apikey:") ||
    k.startsWith("ratelimit:") ||
    k.startsWith("locked:") ||
    k.startsWith("perm:") ||
    k.startsWith("advertise:") ||
    k.startsWith("stats:")
  );
  
  if (testKeys.length > 0) {
    await redis.del(testKeys);
  }
};

/**
 * Wait for a specific condition to be true
 */
export const waitFor = async (
  condition: () => boolean | Promise<boolean>,
  timeout: number = 5000,
  interval: number = 100
): Promise<void> => {
  const startTime = Date.now();
  
  while (Date.now() - startTime < timeout) {
    if (await condition()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
  
  throw new Error("Timeout waiting for condition");
};

/**
 * Check if Redis is available
 */
export const isRedisAvailable = async (redisUrl: string): Promise<boolean> => {
  try {
    const client = createClient({ url: redisUrl });
    await client.connect();
    await client.ping();
    await client.quit();
    return true;
  } catch {
    return false;
  }
};

/**
 * Assert that a response has a specific status code
 */
export const expectStatus = async (
  response: Response,
  expectedStatus: number
): Promise<void> => {
  if (response.status !== expectedStatus) {
    const body = await response.text();
    throw new Error(
      `Expected status ${expectedStatus}, got ${response.status}. Body: ${body}`
    );
  }
};

/**
 * Helper to mock fetch for external API calls
 */
export const createFetchMock = (
  handlers: Array<{
    pattern: string | RegExp;
    response: Response;
  }>
): typeof fetch => {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = input.toString();
    
    for (const handler of handlers) {
      const matches = typeof handler.pattern === "string"
        ? url.includes(handler.pattern)
        : handler.pattern.test(url);
      
      if (matches) {
        return handler.response;
      }
    }
    
    // Default: return 404
    return new Response("Not found", { status: 404 });
  };
};
