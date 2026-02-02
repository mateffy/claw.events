import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import type { Server } from "bun";
import { createClient, type RedisClientType } from "redis";

// Test configuration
const TEST_PORT = parseInt(process.env.PORT || "3001");
const TEST_API_URL = `http://localhost:${TEST_PORT}`;

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

describe("Profile and Locks Endpoints", () => {
  let server: Server;
  let redis: RedisClientType;
  let originalEnv: Record<string, string | undefined>;
  let jwtSecret: string;

  beforeAll(async () => {
    originalEnv = { ...process.env };
    
    process.env.PORT = String(TEST_PORT);
    jwtSecret = "test-jwt-secret-for-testing-only";
    process.env.JWT_SECRET = jwtSecret;
    process.env.REDIS_URL = "redis://localhost:6380";
    process.env.CENTRIFUGO_API_URL = "http://localhost:8001/api";
    process.env.CENTRIFUGO_API_KEY = "test-centrifugo-key";
    process.env.MOLTBOOK_API_BASE = "http://localhost:9000/api/v1";
    process.env.MOLTBOOK_API_KEY = "test-moltbook-key";
    process.env.CLAW_DEV_MODE = "true";

    redis = createClient({ url: process.env.REDIS_URL });
    await redis.connect();

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
    process.env = originalEnv;
  });

  beforeEach(async () => {
    // Clean up keys
    const keys = await redis.keys("advertise:*");
    const lockKeys = await redis.keys("locked:*");
    if (keys.length > 0) await redis.del(keys);
    if (lockKeys.length > 0) await redis.del(lockKeys);
  });

  describe("GET /api/profile/:agent", () => {
    it("Test 18.1: GET /api/profile/:agent - Happy Path", async () => {
      const token = await createTestToken("alice", jwtSecret);

      // Create some advertisements for alice
      await fetch(`${TEST_API_URL}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: "My updates" 
        }),
      });

      await fetch(`${TEST_API_URL}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.data", 
          description: "My data" 
        }),
      });

      const response = await fetch(`${TEST_API_URL}/api/profile/alice`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.agent).toBe("alice");
      expect(body.channels).toBeDefined();
      expect(body.channels.length).toBe(2);
      expect(body.count).toBe(2);
    });

    it("Test 18.2: GET /api/profile/:agent - Empty Profile", async () => {
      const response = await fetch(`${TEST_API_URL}/api/profile/newuser123`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.channels).toEqual([]);
      expect(body.count).toBe(0);
    });

    it("Test 18.3: GET /api/profile/:agent - Sorted by updatedAt", async () => {
      const token = await createTestToken("sortuser", jwtSecret);

      // Create ads with delays
      await fetch(`${TEST_API_URL}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.sortuser.first", 
          description: "First" 
        }),
      });

      await new Promise((resolve) => setTimeout(resolve, 100));

      await fetch(`${TEST_API_URL}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.sortuser.second", 
          description: "Second" 
        }),
      });

      const response = await fetch(`${TEST_API_URL}/api/profile/sortuser`);

      const body = await response.json();
      // Should be sorted newest first
      expect(body.channels[0].channel).toBe("agent.sortuser.second");
      expect(body.channels[1].channel).toBe("agent.sortuser.first");
    });
  });

  describe("GET /api/locks/:agent", () => {
    it("Test 19.1: GET /api/locks/:agent - Happy Path", async () => {
      const token = await createTestToken("lockuser", jwtSecret);

      // Lock several channels
      await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.lockuser.private1" }),
      });

      await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.lockuser.private2" }),
      });

      const response = await fetch(`${TEST_API_URL}/api/locks/lockuser`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.agent).toBe("lockuser");
      expect(body.lockedChannels).toBeDefined();
      expect(body.lockedChannels.length).toBe(2);
      expect(body.count).toBe(2);
    });

    it("Test 19.2: GET /api/locks/:agent - No Locked Channels", async () => {
      const response = await fetch(`${TEST_API_URL}/api/locks/newuser456`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.lockedChannels).toEqual([]);
      expect(body.count).toBe(0);
    });

    it("Test 19.3: GET /api/locks/:agent - Full Channel Names", async () => {
      const token = await createTestToken("fullname", jwtSecret);

      await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.fullname.test" }),
      });

      const response = await fetch(`${TEST_API_URL}/api/locks/fullname`);

      const body = await response.json();
      expect(body.lockedChannels).toContain("agent.fullname.test");
    });
  });
});
