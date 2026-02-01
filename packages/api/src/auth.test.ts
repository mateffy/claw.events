import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, mock } from "bun:test";
import type { Server } from "bun";
import { createClient, type RedisClientType } from "redis";

// Test configuration
const TEST_API_URL = "http://localhost:3001";
const TEST_PORT = 3001;

describe("Authentication Endpoints", () => {
  let server: Server;
  let redis: RedisClientType;
  let originalEnv: Record<string, string | undefined>;

  beforeAll(async () => {
    // Save original environment
    originalEnv = { ...process.env };
    
    // Set test environment variables
    process.env.PORT = String(TEST_PORT);
    process.env.JWT_SECRET = "test-jwt-secret-for-testing-only";
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
    const keys = await redis.keys("authsig:*");
    if (keys.length > 0) {
      await redis.del(keys);
    }
  });

  afterEach(async () => {
    // Clean up Redis after each test
    const keys = await redis.keys("authsig:*");
    if (keys.length > 0) {
      await redis.del(keys);
    }
  });

  describe("POST /auth/init", () => {
    it("Test 1.1: POST /auth/init - Happy Path", async () => {
      const response = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "testuser" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.username).toBe("testuser");
      expect(body.signature).toMatch(/^claw-sig-[A-Za-z0-9_-]+$/);
      expect(body.instructions).toContain(body.signature);
    });

    it("Test 1.2: POST /auth/init - Missing Username", async () => {
      const response = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("username required");
    });

    it("Test 1.3: POST /auth/init - Empty Username", async () => {
      const response = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "" }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("username required");
    });

    it("Test 1.4: POST /auth/init - Whitespace-only Username", async () => {
      const response = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "   " }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("username required");
    });

    it("Test 1.5: POST /auth/init - Very Long Username", async () => {
      const longUsername = "a".repeat(1000);
      const response = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: longUsername }),
      });

      // Current implementation accepts long usernames
      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.username).toBe(longUsername);
    });

    it("Test 1.6: POST /auth/init - Special Characters in Username", async () => {
      const response = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "test@user#123" }),
      });

      // Current implementation accepts special characters
      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.username).toBe("test@user#123");
    });

    it("Test 1.7: POST /auth/init - Signature Uniqueness", async () => {
      const response1 = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "uniqueuser" }),
      });

      const response2 = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "uniqueuser" }),
      });

      const body1 = await response1.json();
      const body2 = await response2.json();

      expect(body1.signature).not.toBe(body2.signature);
    });

    it("Test 1.8: POST /auth/init - Redis TTL Verification", async () => {
      await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "ttluser" }),
      });

      const ttl = await redis.ttl("authsig:ttluser");
      expect(ttl).toBeGreaterThan(590); // Should be around 600 seconds
      expect(ttl).toBeLessThanOrEqual(600);
    });

    it("Test 1.9: POST /auth/init - Signature Overwrites Previous", async () => {
      const response1 = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "overwriteuser" }),
      });

      const body1 = await response1.json();

      await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "overwriteuser" }),
      });

      const storedSignature = await redis.get("authsig:overwriteuser");
      expect(storedSignature).not.toBe(body1.signature);
      expect(storedSignature).toMatch(/^claw-sig-[A-Za-z0-9_-]+$/);
    });
  });

  describe("POST /auth/verify", () => {
    it("Test 2.1: POST /auth/verify - Happy Path", async () => {
      // First init auth
      const initResponse = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "verifyuser" }),
      });
      const initBody = await initResponse.json();
      const signature = initBody.signature;

      // Mock MaltBook API to return profile with signature
      const mockFetch = mock(fetch, (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("moltbook.com/api/v1/agents/profile")) {
          return Promise.resolve(new Response(
            JSON.stringify({
              success: true,
              agent: {
                description: `Test profile with signature: ${signature}`,
              },
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      // Verify auth
      const response = await fetch(`${TEST_API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "verifyuser" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.token).toBeDefined();
      expect(typeof body.token).toBe("string");

      mockFetch.restore();
    });

    it("Test 2.2: POST /auth/verify - JWT Token Structure", async () => {
      // First init auth
      const initResponse = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "jwtuser" }),
      });
      const initBody = await initResponse.json();
      const signature = initBody.signature;

      // Mock MaltBook API
      const mockFetch = mock(fetch, (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("agents/profile")) {
          return Promise.resolve(new Response(
            JSON.stringify({
              success: true,
              agent: { description: `Profile ${signature}` },
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      const response = await fetch(`${TEST_API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "jwtuser" }),
      });

      const body = await response.json();
      const token = body.token;

      // Decode JWT (without verification)
      const parts = token.split(".");
      expect(parts.length).toBe(3);

      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());

      expect(header.alg).toBe("HS256");
      expect(payload.sub).toBe("jwtuser");
      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBeDefined();
      expect(payload.exp - payload.iat).toBe(7 * 24 * 60 * 60); // 7 days

      mockFetch.restore();
    });

    it("Test 2.3: POST /auth/verify - Missing Username", async () => {
      const response = await fetch(`${TEST_API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("username required");
    });

    it("Test 2.4: POST /auth/verify - No Pending Signature", async () => {
      const response = await fetch(`${TEST_API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "nosiguser" }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("no pending signature");
    });

    it("Test 2.5: POST /auth/verify - Expired Signature", async () => {
      // Init auth
      await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "expireduser" }),
      });

      // Manually expire the signature
      await redis.expire("authsig:expireduser", 1);

      // Wait for expiry
      await new Promise((resolve) => setTimeout(resolve, 1100));

      const response = await fetch(`${TEST_API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "expireduser" }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("no pending signature");
    });

    it("Test 2.6: POST /auth/verify - Signature Not in MaltBook Profile", async () => {
      // Init auth
      const initResponse = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "nosigprofileuser" }),
      });
      const initBody = await initResponse.json();

      // Mock MaltBook API to return profile WITHOUT signature
      const mockFetch = mock(fetch, (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("agents/profile")) {
          return Promise.resolve(new Response(
            JSON.stringify({
              success: true,
              agent: { description: "Profile without signature" },
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      const response = await fetch(`${TEST_API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "nosigprofileuser" }),
      });

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toContain("signature not found");

      mockFetch.restore();
    });

    it("Test 2.7: POST /auth/verify - MaltBook API Key Missing", async () => {
      // Save original key
      const originalKey = process.env.MOLTBOOK_API_KEY;
      process.env.MOLTBOOK_API_KEY = "";

      // Init auth
      await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "noapikeyuser" }),
      });

      const response = await fetch(`${TEST_API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "noapikeyuser" }),
      });

      expect(response.status).toBe(500);
      const body = await response.json();
      expect(body.error).toContain("MOLTBOOK_API_KEY not configured");

      // Restore key
      process.env.MOLTBOOK_API_KEY = originalKey;
    });

    it("Test 2.8: POST /auth/verify - MaltBook API Failure (502)", async () => {
      // Init auth
      const initResponse = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "apierroruser" }),
      });
      const initBody = await initResponse.json();

      // Mock MaltBook API to return 500 error
      const mockFetch = mock(fetch, (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("agents/profile")) {
          return Promise.resolve(new Response(
            JSON.stringify({ error: "Internal Server Error" }),
            { status: 500, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      const response = await fetch(`${TEST_API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "apierroruser" }),
      });

      expect(response.status).toBe(502);
      const body = await response.json();
      expect(body.error).toContain("profile fetch failed (500)");

      mockFetch.restore();
    });

    it("Test 2.9: POST /auth/verify - MaltBook Returns 404", async () => {
      // Init auth
      await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "nonexistentuser" }),
      });

      // Mock MaltBook API to return 404
      const mockFetch = mock(fetch, (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("agents/profile")) {
          return Promise.resolve(new Response(
            JSON.stringify({ error: "Agent not found" }),
            { status: 404, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      const response = await fetch(`${TEST_API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "nonexistentuser" }),
      });

      expect(response.status).toBe(502);
      const body = await response.json();
      expect(body.error).toContain("profile fetch failed (404)");

      mockFetch.restore();
    });

    it("Test 2.10: POST /auth/verify - Redis Cleanup After Success", async () => {
      // Init auth
      const initResponse = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "cleanupuser" }),
      });
      const initBody = await initResponse.json();
      const signature = initBody.signature;

      // Mock MaltBook API
      const mockFetch = mock(fetch, (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("agents/profile")) {
          return Promise.resolve(new Response(
            JSON.stringify({
              success: true,
              agent: { description: `Profile ${signature}` },
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      // Verify
      await fetch(`${TEST_API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "cleanupuser" }),
      });

      // Check Redis key is deleted
      const exists = await redis.exists("authsig:cleanupuser");
      expect(exists).toBe(0);

      mockFetch.restore();
    });

    it("Test 2.11: POST /auth/verify - Cannot Reuse Signature", async () => {
      // Init auth
      const initResponse = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "reuseuser" }),
      });
      const initBody = await initResponse.json();
      const signature = initBody.signature;

      // Mock MaltBook API
      const mockFetch = mock(fetch, (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("agents/profile")) {
          return Promise.resolve(new Response(
            JSON.stringify({
              success: true,
              agent: { description: `Profile ${signature}` },
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      // First verify - should succeed
      const response1 = await fetch(`${TEST_API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "reuseuser" }),
      });
      expect(response1.status).toBe(200);

      // Second verify - should fail (no pending signature)
      const response2 = await fetch(`${TEST_API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "reuseuser" }),
      });
      expect(response2.status).toBe(400);
      const body2 = await response2.json();
      expect(body2.error).toBe("no pending signature");

      mockFetch.restore();
    });

    it("Test 2.12: POST /auth/verify - Wrong Username", async () => {
      // Init auth for user A
      await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "userA" }),
      });

      // Try to verify as user B
      const response = await fetch(`${TEST_API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "userB" }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("no pending signature");
    });

    it("Test 2.13: POST /auth/verify - Partial Signature Match", async () => {
      // Init auth
      const initResponse = await fetch(`${TEST_API_URL}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "partialuser" }),
      });
      const initBody = await initResponse.json();

      // Mock MaltBook API with partial signature
      const mockFetch = mock(fetch, (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        if (url.includes("agents/profile")) {
          return Promise.resolve(new Response(
            JSON.stringify({
              success: true,
              agent: { description: "Profile with claw-sig" }, // Partial signature
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          ));
        }
        return Promise.resolve(new Response("Not found", { status: 404 }));
      });

      const response = await fetch(`${TEST_API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "partialuser" }),
      });

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toContain("signature not found");

      mockFetch.restore();
    });
  });

  describe("POST /auth/dev-register", () => {
    it("Test 3.1: POST /auth/dev-register - Happy Path", async () => {
      const response = await fetch(`${TEST_API_URL}/auth/dev-register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "devuser" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.token).toBeDefined();
      expect(typeof body.token).toBe("string");
    });

    it("Test 3.2: POST /auth/dev-register - Dev Mode Disabled", async () => {
      // Disable dev mode
      process.env.CLAW_DEV_MODE = "false";

      const response = await fetch(`${TEST_API_URL}/auth/dev-register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "devuser2" }),
      });

      expect(response.status).toBe(404);
      const body = await response.json();
      expect(body.error).toBe("not available");

      // Re-enable dev mode
      process.env.CLAW_DEV_MODE = "true";
    });

    it("Test 3.3: POST /auth/dev-register - Missing Username", async () => {
      const response = await fetch(`${TEST_API_URL}/auth/dev-register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("username required");
    });

    it("Test 3.4: POST /auth/dev-register - Dev Token Same Structure", async () => {
      const response = await fetch(`${TEST_API_URL}/auth/dev-register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "devuser3" }),
      });

      const body = await response.json();
      const token = body.token;

      // Decode JWT
      const parts = token.split(".");
      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());

      expect(header.alg).toBe("HS256");
      expect(payload.sub).toBe("devuser3");
      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBeDefined();
    });
  });
});
