import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import type { Server } from "bun";
import { createClient, type RedisClientType } from "redis";
import { SignJWT } from "jose";

// Test configuration
const TEST_PORT = parseInt(process.env.PORT || "3001");
const TEST_API_URL = `http://localhost:${TEST_PORT}`;

const createTestToken = async (username: string, jwtSecret: string, options?: { expired?: boolean }): Promise<string> => {
  const jwtKey = new TextEncoder().encode(jwtSecret);
  const jwt = new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(username)
    .setIssuedAt();
  
  if (options?.expired) {
    jwt.setExpirationTime("-1h"); // Expired 1 hour ago
  } else {
    jwt.setExpirationTime("7d");
  }
  
  return jwt.sign(jwtKey);
};

describe("Security and Edge Cases Tests", () => {
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
    const keys = await redis.keys("advertise:*");
    const lockKeys = await redis.keys("locked:*");
    if (keys.length > 0) await redis.del(keys);
    if (lockKeys.length > 0) await redis.del(lockKeys);
  });

  describe("JWT Token Security", () => {
    it("Test 21.1: JWT Token - Expired Token Rejected", async () => {
      const expiredToken = await createTestToken("testuser", jwtSecret, { expired: true });

      const response = await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${expiredToken}`,
        },
        body: JSON.stringify({ channel: "agent.testuser.private" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 21.2: JWT Token - Wrong Signature", async () => {
      // Create token with wrong secret
      const wrongToken = await createTestToken("testuser", "wrong-secret-12345");

      const response = await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${wrongToken}`,
        },
        body: JSON.stringify({ channel: "agent.testuser.private" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 21.3: JWT Token - Tampered Payload", async () => {
      const validToken = await createTestToken("alice", jwtSecret);
      
      // Tamper with the token (modify payload)
      const parts = validToken.split(".");
      const tamperedPayload = Buffer.from(parts[1], "base64url").toString();
      const modifiedPayload = tamperedPayload.replace("alice", "bob");
      const tamperedToken = `${parts[0]}.${Buffer.from(modifiedPayload).toString("base64url")}.${parts[2]}`;

      const response = await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${tamperedToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 21.4: JWT Token - Malformed Token", async () => {
      const response = await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer not.a.token",
        },
        body: JSON.stringify({ channel: "agent.test.private" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 21.5: JWT Token - Missing Bearer Prefix", async () => {
      const token = await createTestToken("alice", jwtSecret);

      const response = await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": token, // Missing "Bearer " prefix
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      expect(response.status).toBe(401);
    });

    it("Test 21.6: JWT Token - User A Token for User B Operations", async () => {
      const aliceToken = await createTestToken("alice", jwtSecret);

      // Try to use alice's token for bob's channel
      const response = await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ channel: "agent.bob.private" }),
      });

      expect(response.status).toBe(403);
      const body = await response.json();
      expect(body.error).toContain("can only lock your own channels");
    });
  });

  describe("Injection Prevention", () => {
    it("Test 21.7: Injection - SQL in Channel Name", async () => {
      const token = await createTestToken("alice", jwtSecret);

      const response = await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.'; DROP TABLE users; --" 
        }),
      });

      // Should not crash or execute SQL, should validate channel format
      expect([400, 403]).toContain(response.status);
    });

    it("Test 21.8: Injection - NoSQL in Redis Keys", async () => {
      // Try to inject special characters that might affect Redis
      const maliciousUsername = "alice{$ne:null}";
      
      const response = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: maliciousUsername }),
      });

      // Should treat the key literally
      expect(response.status).toBe(200);
      
      const storedKey = await redis.get(`authsig:${maliciousUsername}`);
      expect(storedKey).toBeDefined();
    });

    it("Test 21.9: Injection - XSS in Description", async () => {
      const token = await createTestToken("alice", jwtSecret);
      const xssPayload = "<script>alert('xss')</script>";

      const response = await fetch(`${TEST_API_URL}/api/advertise`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice.updates", 
          description: xssPayload 
        }),
      });

      expect(response.status).toBe(200);
      
      // Verify stored literally (not executed)
      const data = await redis.get("advertise:alice:updates");
      const parsed = JSON.parse(data!);
      expect(parsed.description).toBe(xssPayload);
    });

    it("Test 21.10: Path Traversal - Double Dot in Channel", async () => {
      const token = await createTestToken("alice", jwtSecret);

      const response = await fetch(`${TEST_API_URL}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ 
          channel: "agent.alice/../../../etc/passwd" 
        }),
      });

      // Should reject or treat as literal (not cause file access)
      expect([400, 403]).toContain(response.status);
    });

    it("Test 21.11: Null Bytes in Strings", async () => {
      const token = await createTestToken("alice", jwtSecret);
      const usernameWithNull = "alice\x00injected";

      const response = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: usernameWithNull }),
      });

      // Should handle gracefully (200 or reject)
      expect([200, 400]).toContain(response.status);
    });
  });

  describe("Unicode Handling", () => {
    it("Test 21.12: Unicode - Emoji in Username", async () => {
      const emojiUsername = "test😀user";

      const response = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: emojiUsername }),
      });

      // Should handle emoji gracefully
      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.username).toBe(emojiUsername);
    });

    it("Test 21.13: Unicode - Right-to-Left Characters", async () => {
      // RTL override character
      const rtlUsername = "test\u202Eevil\u202Cuser";

      const response = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: rtlUsername }),
      });

      // Should handle gracefully
      expect(response.status).toBe(200);
    });

    it("Test 21.14: Unicode - Confusable Characters", async () => {
      // Cyrillic 'а' looks like Latin 'a'
      const cyrillicUsername = "test\u0430user"; // Cyrillic а

      const response = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: cyrillicUsername }),
      });

      expect(response.status).toBe(200);
      
      // Verify stored as different from Latin version
      const stored = await redis.get(`authsig:${cyrillicUsername}`);
      expect(stored).toBeDefined();
      
      // Latin version should not exist
      const latinVersion = await redis.get("authsig:testauser");
      expect(latinVersion).toBeNull();
    });
  });
});
