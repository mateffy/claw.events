import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import type { Server } from "bun";
import { createClient, type RedisClientType } from "redis";

// Test configuration
const TEST_API_URL = "http://localhost:3001";
const TEST_PORT = 3001;

// Helper function to create a valid token
const createTestToken = async (username: string, jwtSecret: string): Promise<string> => {
  const { SignJWT } = await import("jose");
  const jwtKey = new TextEncoder().encode(jwtSecret);
  return new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(username)
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(jwtKey);
};

describe("Proxy Endpoints (Centrifugo Integration)", () => {
  let server: Server;
  let redis: RedisClientType;
  let originalEnv: Record<string, string | undefined>;
  let jwtSecret: string;

  beforeAll(async () => {
    // Save original environment
    originalEnv = { ...process.env };
    
    // Set test environment variables
    process.env.PORT = String(TEST_PORT);
    jwtSecret = "test-jwt-secret-for-testing-only";
    process.env.JWT_SECRET = jwtSecret;
    process.env.REDIS_URL = "redis://localhost:6380";
    process.env.CENTRIFUGO_API_URL = "http://localhost:8001/api";
    process.env.CENTRIFUGO_API_KEY = "test-centrifugo-key";
    process.env.MOLTBOOK_API_BASE = "http://localhost:9000/api/v1";
    process.env.MOLTBOOK_API_KEY = "test-moltbook-key";
    process.env.CLAW_DEV_MODE = "true";

    // Connect to Redis
    redis = createClient({ url: process.env.REDIS_URL });
    await redis.connect();

    // Import and start server
    const { default: app } = await import("./index.ts");
    server = Bun.serve({
      fetch: app.fetch,
      port: TEST_PORT,
    });
  });

  afterAll(async () => {
    if (server) {
      server.stop();
    }
    if (redis) {
      await redis.quit();
    }
    // Restore original environment
    process.env = originalEnv;
  });

  beforeEach(async () => {
    // Clean up Redis before each test
    const lockKeys = await redis.keys("locked:*");
    const permKeys = await redis.keys("perm:*");
    if (lockKeys.length > 0) {
      await redis.del(lockKeys);
    }
    if (permKeys.length > 0) {
      await redis.del(permKeys);
    }
  });

  describe("POST /proxy/subscribe", () => {
    it("Test 4.1: POST /proxy/subscribe - Public Channel (public.*)", async () => {
      const response = await fetch(`${TEST_API_URL}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "public.townsquare", user: "anyone" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
      expect(body.error).toBeUndefined();
    });

    it("Test 4.2: POST /proxy/subscribe - Public Channel Anonymous", async () => {
      const response = await fetch(`${TEST_API_URL}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "public.test", user: "" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
    });

    it("Test 4.3: POST /proxy/subscribe - System Channel (system.*)", async () => {
      const response = await fetch(`${TEST_API_URL}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "system.timer.minute", user: "anyone" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
    });

    it("Test 4.4: POST /proxy/subscribe - Unlocked Agent Channel", async () => {
      // Create an unlocked agent channel (do not lock it)
      const response = await fetch(`${TEST_API_URL}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.updates", user: "bob" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
    });

    it("Test 4.5: POST /proxy/subscribe - Unlocked Agent Channel Anonymous", async () => {
      const response = await fetch(`${TEST_API_URL}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.updates", user: "" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
    });

    it("Test 4.6: POST /proxy/subscribe - Locked Agent Channel Owner", async () => {
      // Lock the channel as alice
      const token = await createTestToken("alice", jwtSecret);
      await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      const response = await fetch(`${TEST_API_URL}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.private", user: "alice" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
    });

    it("Test 4.7: POST /proxy/subscribe - Locked Agent Channel Granted User", async () => {
      // Lock and grant access as alice
      const token = await createTestToken("alice", jwtSecret);
      await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      await fetch(`${TEST_API_URL}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.private" }),
      });

      const response = await fetch(`${TEST_API_URL}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.private", user: "bob" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
    });

    it("Test 4.8: POST /proxy/subscribe - Locked Agent Channel Non-Granted User", async () => {
      // Lock as alice
      const token = await createTestToken("alice", jwtSecret);
      await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      // Try to subscribe as charlie (not granted)
      const response = await fetch(`${TEST_API_URL}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.private", user: "charlie" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe(403);
      expect(body.error.message).toContain("permission denied");
    });

    it("Test 4.9: POST /proxy/subscribe - Locked Agent Channel Anonymous", async () => {
      // Lock as alice
      const token = await createTestToken("alice", jwtSecret);
      await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      // Try to subscribe as anonymous
      const response = await fetch(`${TEST_API_URL}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.private", user: "" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe(403);
    });

    it("Test 4.10: POST /proxy/subscribe - Missing Channel", async () => {
      const response = await fetch(`${TEST_API_URL}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user: "alice" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe(403);
    });

    it("Test 4.11: POST /proxy/subscribe - Invalid Channel Format", async () => {
      const response = await fetch(`${TEST_API_URL}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "invalid-channel", user: "alice" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe(403);
    });

    it("Test 4.12: POST /proxy/subscribe - Agent Channel Wrong Owner (Unlocked)", async () => {
      // For unlocked channels, anyone can subscribe
      const response = await fetch(`${TEST_API_URL}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.bob.test", user: "alice" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
    });
  });

  describe("POST /proxy/publish", () => {
    it("Test 5.1: POST /proxy/publish - Public Channel Anyone", async () => {
      const response = await fetch(`${TEST_API_URL}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "public.townsquare", user: "anyone" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
    });

    it("Test 5.2: POST /proxy/publish - System Channel Denied", async () => {
      const response = await fetch(`${TEST_API_URL}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "system.timer.minute", user: "alice" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe(403);
    });

    it("Test 5.3: POST /proxy/publish - Agent Channel Owner", async () => {
      const response = await fetch(`${TEST_API_URL}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.updates", user: "alice" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
    });

    it("Test 5.4: POST /proxy/publish - Agent Channel Non-Owner", async () => {
      const response = await fetch(`${TEST_API_URL}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.updates", user: "bob" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe(403);
    });

    it("Test 5.5: POST /proxy/publish - Locked Agent Channel Owner Can Still Publish", async () => {
      // Lock the channel as alice
      const token = await createTestToken("alice", jwtSecret);
      await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      const response = await fetch(`${TEST_API_URL}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.private", user: "alice" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
    });

    it("Test 5.6: POST /proxy/publish - Locked Agent Channel Non-Owner Still Denied", async () => {
      // Lock and grant subscribe access to bob
      const token = await createTestToken("alice", jwtSecret);
      await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      await fetch(`${TEST_API_URL}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.private" }),
      });

      // Try to publish as bob
      const response = await fetch(`${TEST_API_URL}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.private", user: "bob" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe(403);
    });

    it("Test 5.7: POST /proxy/publish - Anonymous to Agent Channel", async () => {
      const response = await fetch(`${TEST_API_URL}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.updates", user: "" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe(403);
    });

    it("Test 5.8: POST /proxy/publish - Missing Channel", async () => {
      const response = await fetch(`${TEST_API_URL}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user: "alice" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe(403);
    });
  });
});
