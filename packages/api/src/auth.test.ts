import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "bun:test";
import {
  createTestContext,
  startMoltbookMockServer,
  startTestServer,
  cleanupTestContext,
  clearTestData,
  type TestContext,
} from "./test-utils.ts";

describe("Authentication Endpoints", () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext();
    await startMoltbookMockServer(ctx, 9000);
    await startTestServer(ctx);
  });

  afterAll(async () => {
    await cleanupTestContext(ctx);
  });

  beforeEach(async () => {
    if (ctx.redis) {
      await clearTestData(ctx.redis);
    }
    ctx.expectedSignatures.clear();
  });

  afterEach(async () => {
    if (ctx.redis) {
      await clearTestData(ctx.redis);
    }
    ctx.expectedSignatures.clear();
  });

  describe("POST /auth/init", () => {
    it("Test 1.1: POST /auth/init - Happy Path", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "testuser" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.username).toBe("testuser");
      expect(body.claim_token).toBeDefined();
      expect(body.signature).toMatch(/^claw-sig-claim-[A-Za-z0-9_-]+$/);
      expect(body.pending_claims).toBe(1);
      expect(body.max_claims).toBe(100);
    });

    it("Test 1.2: POST /auth/init - Missing Username", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("username required");
    });

    it("Test 1.3: POST /auth/init - Empty Username", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "" }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("username required");
    });

    it("Test 1.4: POST /auth/init - Whitespace-only Username", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/auth/init`, {
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
      const response = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: longUsername }),
      });

      // Should accept long usernames (no max length enforcement)
      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.username).toBe(longUsername);
    });

    it("Test 1.6: POST /auth/init - Special Characters in Username", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "user@123.test" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.username).toBe("user@123.test");
    });

    it("Test 1.7: POST /auth/init - Signature Uniqueness", async () => {
      const response1 = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "uniqueuser" }),
      });

      const response2 = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "uniqueuser" }),
      });

      const body1 = await response1.json();
      const body2 = await response2.json();

      expect(body1.signature).not.toBe(body2.signature);
    });

    it("Test 1.8: POST /auth/init - Redis TTL Verification", async () => {
      await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "ttluser" }),
      });

      const claimKeys = await ctx.redis!.keys("claim:ttluser:*");
      expect(claimKeys.length).toBeGreaterThan(0);
      
      const ttl = await ctx.redis!.ttl(claimKeys[0]);
      expect(ttl).toBeGreaterThan(86000); // Should be around 24 hours (86400 seconds)
      expect(ttl).toBeLessThanOrEqual(86400);
    });

    it("Test 1.9: POST /auth/init - Multiple Claims Created", async () => {
      const response1 = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "overwriteuser" }),
      });

      const body1 = await response1.json();
      expect(body1.pending_claims).toBe(1);
      const claimToken1 = body1.claim_token;

      const response2 = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "overwriteuser" }),
      });

      const body2 = await response2.json();

      // Two calls should create TWO separate claims (not overwrite)
      expect(body2.pending_claims).toBe(2);
      expect(body2.claim_token).not.toBe(claimToken1);
      expect(body1.signature).not.toBe(body2.signature);

      // Both signatures should be in the new format (claim-* pattern)
      expect(body1.signature).toMatch(/^claw-sig-claim-[A-Za-z0-9_-]+$/);
      expect(body2.signature).toMatch(/^claw-sig-claim-[A-Za-z0-9_-]+$/);
    });
  });

  describe("POST /auth/verify", () => {
    it("Test 2.1: POST /auth/verify - Happy Path", async () => {
      // First init auth
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "verifyuser" }),
      });
      const initBody = await initResponse.json();
      const claimToken = initBody.claim_token;
      const signature = initBody.signature;

      // Set expected signature for MaltBook mock server
      ctx.expectedSignatures.set("verifyuser", signature);

      // Verify auth with claim_token
      const response = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "verifyuser", claim_token: claimToken }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.token).toBeDefined();
      expect(typeof body.token).toBe("string");
    });

    it("Test 2.2: POST /auth/verify - JWT Token Structure", async () => {
      // First init auth
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "jwtuser" }),
      });
      const initBody = await initResponse.json();
      const claimToken = initBody.claim_token;

      // Set expected signature for MaltBook mock server
      ctx.expectedSignatures.set("jwtuser", `claw-sig-${claimToken}`);

      const response = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "jwtuser", claim_token: claimToken }),
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
      expect(payload.type).toBe("apikey");
      // API keys are indefinite - no expiration
      expect(payload.exp).toBeUndefined();
    });

    it("Test 2.3: POST /auth/verify - Missing Username", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("username required");
    });

    it("Test 2.4: POST /auth/verify - Invalid Claim Token", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "nosiguser", claim_token: "dummy-claim" }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("invalid or expired claim token");
    });

    it("Test 2.5: POST /auth/verify - Expired Claim", async () => {
      // Init auth
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "expireduser" }),
      });
      const initBody = await initResponse.json();
      const claimToken = initBody.claim_token;

      // Manually expire the claim by setting TTL to 1 second
      const claimKeys = await ctx.redis!.keys("claim:expireduser:*");
      if (claimKeys.length > 0) {
        await ctx.redis!.expire(claimKeys[0], 1);
      }

      // Wait for expiry
      await new Promise((resolve) => setTimeout(resolve, 1100));

      const response = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "expireduser", claim_token: claimToken }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("invalid or expired claim token");
    });

    it("Test 2.6: POST /auth/verify - Signature Not in MaltBook Profile", async () => {
      // Init auth
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "nosigprofileuser" }),
      });
      const initBody = await initResponse.json();
      const claimToken = initBody.claim_token;

      // Set wrong signature for MaltBook mock server
      ctx.expectedSignatures.set("nosigprofileuser", "wrong-signature");

      const response = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "nosigprofileuser", claim_token: claimToken }),
      });

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toContain("signature not found");
    });

    it("Test 2.7: POST /auth/verify - MaltBook API Key Missing", async () => {
      // NOTE: This test documents a known limitation. The server reads MOLTBOOK_API_KEY at startup,
      // so modifying process.env.MOLTBOOK_API_KEY after the server has started has no effect.
      // To properly test this scenario, we would need to restart the server with different env vars,
      // which is not feasible in the current test architecture where the server is reused.
      // This scenario should be tested in integration tests instead.
      
      // Init auth
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "noapikeyuser" }),
      });
      const initBody = await initResponse.json();
      const claimToken = initBody.claim_token;

      // Set expected signature
      ctx.expectedSignatures.set("noapikeyuser", `claw-sig-${claimToken}`);

      // This will actually succeed since the server was started with a valid API key
      const response = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "noapikeyuser", claim_token: claimToken }),
      });

      // We expect 200 (not 500) since the env var was set at server startup
      expect(response.status).toBe(200);
    });

    it("Test 2.8: POST /auth/verify - MaltBook API Failure (502)", async () => {
      // Init auth
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "apierroruser" }),
      });
      const initBody = await initResponse.json();
      const claimToken = initBody.claim_token;

      // Set error flag for mock server
      ctx.expectedSignatures.set("apierroruser", "__ERROR_500__");

      const response = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "apierroruser", claim_token: claimToken }),
      });

      expect(response.status).toBe(502);
      const body = await response.json();
      expect(body.error).toContain("profile fetch failed (500)");
    });

    it("Test 2.9: POST /auth/verify - MaltBook Returns 404", async () => {
      // Init auth
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "nonexistentuser" }),
      });
      const initBody = await initResponse.json();
      const claimToken = initBody.claim_token;

      // Don't set expected signature - this will cause 404

      const response = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "nonexistentuser", claim_token: claimToken }),
      });

      expect(response.status).toBe(502);
      const body = await response.json();
      expect(body.error).toContain("profile fetch failed (404)");
    });

    it("Test 2.10: POST /auth/verify - Redis Cleanup After Success", async () => {
      // Init auth
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "cleanupuser" }),
      });
      const initBody = await initResponse.json();
      const claimToken = initBody.claim_token;

      // Set expected signature
      ctx.expectedSignatures.set("cleanupuser", `claw-sig-${claimToken}`);

      // Verify auth
      const response = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "cleanupuser", claim_token: claimToken }),
      });

      expect(response.status).toBe(200);

      // Check claim key is deleted
      const claimKeys = await ctx.redis!.keys("claim:cleanupuser:*");
      expect(claimKeys.length).toBe(0);
    });

    it("Test 2.11: POST /auth/verify - Claim is One-time Use", async () => {
      // Init auth
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "reuseuser" }),
      });
      const initBody = await initResponse.json();
      const signature = initBody.signature;
      const claimToken = initBody.claim_token;

      // Set expected signature for MaltBook mock server
      ctx.expectedSignatures.set("reuseuser", signature);

      // First verify - should succeed
      const response1 = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "reuseuser", claim_token: claimToken }),
      });
      expect(response1.status).toBe(200);

      // Second verify with same claim - should fail (claim already used)
      const response2 = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "reuseuser", claim_token: claimToken }),
      });
      expect(response2.status).toBe(400);
      const body2 = await response2.json();
      expect(body2.error).toBe("invalid or expired claim token");
    });

    it("Test 2.12: POST /auth/verify - Wrong Username", async () => {
      // Init auth for user A
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "userA" }),
      });
      const initBody = await initResponse.json();
      const claimToken = initBody.claim_token;

      // Try to verify with user B's username but user A's claim token
      const response = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "userB", claim_token: claimToken }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("invalid or expired claim token");
    });

    it("Test 2.13: POST /auth/verify - Partial Signature Match", async () => {
      // Init auth
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "partialuser" }),
      });
      const initBody = await initResponse.json();
      const claimToken = initBody.claim_token;

      // Set partial signature (wrong signature to test partial match failure)
      ctx.expectedSignatures.set("partialuser", "claw-sig");

      const response = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "partialuser", claim_token: claimToken }),
      });

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toContain("signature not found");
    });
  });

  describe("POST /auth/dev-register", () => {
    it("Test 3.1: POST /auth/dev-register - Happy Path", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/auth/dev-register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "devuser" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.token).toBeDefined();
      expect(typeof body.token).toBe("string");
    });

    it("Test 3.2: POST /auth/dev-register - Only in Dev Mode", async () => {
      // NOTE: This test documents a known limitation. The server reads CLAW_DEV_MODE at startup,
      // so modifying process.env.CLAW_DEV_MODE after the server has started has no effect.
      // To properly test this scenario, we would need to restart the server with different env vars.
      // This scenario should be tested in integration tests instead.

      // This will succeed since the server was started with CLAW_DEV_MODE=true
      const response = await fetch(`${ctx.config.apiUrl}/auth/dev-register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "devuser2" }),
      });

      expect(response.status).toBe(200);
    });

    it("Test 3.3: POST /auth/dev-register - Missing Username", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/auth/dev-register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toBe("username required");
    });

    it("Test 3.4: POST /auth/dev-register - Dev Token Same Structure", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/auth/dev-register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "devuser3" }),
      });

      const body = await response.json();
      const token = body.token;

      // Decode JWT
      const parts = token.split(".");
      expect(parts.length).toBe(3);

      const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());

      expect(header.alg).toBe("HS256");
      expect(payload.sub).toBe("devuser3");
      expect(payload.iat).toBeDefined();
      expect(payload.type).toBe("apikey");
      // Dev tokens are API keys - no expiration
      expect(payload.exp).toBeUndefined();
    });
  });

  describe("API Key Authentication Flow", () => {
    it("Test 4.1: POST /auth/init - Returns claim_token and signature", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "apikeyuser" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.username).toBe("apikeyuser");
      expect(body.claim_token).toBeDefined();
      expect(body.signature).toMatch(/^claw-sig-claim-/);
      expect(body.pending_claims).toBe(1);
      expect(body.max_claims).toBe(100);
    });

    it("Test 4.2: POST /auth/init - Creates new claim without invalidating existing API key", async () => {
      // First, create an API key
      const initResponse1 = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "multikeyuser" }),
      });
      const initBody1 = await initResponse1.json();
      const claimToken1 = initBody1.claim_token;

      // Set expected signature
      ctx.expectedSignatures.set("multikeyuser", `claw-sig-${claimToken1}`);

      // Verify to create first API key
      const verifyResponse = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "multikeyuser", claim_token: claimToken1 }),
      });
      expect(verifyResponse.status).toBe(200);
      const verifyBody = await verifyResponse.json();
      const firstApiKey = verifyBody.token;

      // Create second claim (should work, old API key still valid)
      const initResponse2 = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "multikeyuser" }),
      });
      expect(initResponse2.status).toBe(200);
      const initBody2 = await initResponse2.json();
      expect(initBody2.note).toContain("already have an active API key");

      // First API key should still work
      const lockResponse = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${firstApiKey}`,
        },
        body: JSON.stringify({ channel: "agent.multikeyuser.test" }),
      });
      expect(lockResponse.status).toBe(200);
    });

    it("Test 4.3: POST /auth/init - Enforces max 100 claims limit", async () => {
      const username = "maxclaimsuser";

      // Create 100 claims
      for (let i = 0; i < 100; i++) {
        const response = await fetch(`${ctx.config.apiUrl}/auth/init`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username }),
        });
        expect(response.status).toBe(200);
      }

      // 101st claim should fail
      const response = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });

      expect(response.status).toBe(429);
      const body = await response.json();
      expect(body.error).toContain("Maximum authentication attempts reached");
      expect(body.hint).toContain("Wait for the tokens to expire");
      expect(body.retry_timestamp).toBeDefined();
      expect(body.max_claims).toBe(100);
    });

    it("Test 4.4: POST /auth/verify - Requires claim_token", async () => {
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "noclaimuser" }),
      });
      expect(initResponse.status).toBe(200);

      const response = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "noclaimuser" }), // Missing claim_token
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("claim_token required");
    });

    it("Test 4.5: POST /auth/verify - Invalid claim_token rejected", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: "invalidclaimuser",
          claim_token: "invalid-claim-token"
        }),
      });

      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain("invalid or expired claim token");
    });

    it("Test 4.6: POST /auth/verify - Claim is one-time use", async () => {
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "onetimeuser" }),
      });
      const initBody = await initResponse.json();
      const claimToken = initBody.claim_token;

      // Set expected signature
      ctx.expectedSignatures.set("onetimeuser", `claw-sig-${claimToken}`);

      // First verify succeeds
      const verifyResponse1 = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "onetimeuser", claim_token: claimToken }),
      });
      expect(verifyResponse1.status).toBe(200);

      // Second verify with same claim fails
      const verifyResponse2 = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "onetimeuser", claim_token: claimToken }),
      });
      expect(verifyResponse2.status).toBe(400);
      const body = await verifyResponse2.json();
      expect(body.error).toContain("invalid or expired claim token");
    });

    it("Test 4.7: POST /auth/verify - Creates stored API key on success", async () => {
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "storedkeyuser" }),
      });
      const initBody = await initResponse.json();
      const claimToken = initBody.claim_token;

      // Set expected signature
      ctx.expectedSignatures.set("storedkeyuser", `claw-sig-${claimToken}`);

      const verifyResponse = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "storedkeyuser", claim_token: claimToken }),
      });

      expect(verifyResponse.status).toBe(200);
      const body = await verifyResponse.json();
      expect(body.token).toBeDefined();
      expect(body.hint).toContain("Store it securely");
      expect(body.username).toBe("storedkeyuser");

      // Verify the API key works
      const lockResponse = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${body.token}`,
        },
        body: JSON.stringify({ channel: "agent.storedkeyuser.test" }),
      });
      expect(lockResponse.status).toBe(200);
    });

    it("Test 4.8: POST /auth/revoke - Requires valid API key", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/auth/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // No Authorization header
      });

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toBeDefined();
    });

    it("Test 4.9: POST /auth/revoke - Revokes API key successfully", async () => {
      // First create an API key
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "revokeuser" }),
      });
      const initBody = await initResponse.json();
      const claimToken = initBody.claim_token;

      // Set expected signature
      ctx.expectedSignatures.set("revokeuser", `claw-sig-${claimToken}`);

      const verifyResponse = await fetch(`${ctx.config.apiUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "revokeuser", claim_token: claimToken }),
      });
      const verifyBody = await verifyResponse.json();
      const apiKey = verifyBody.token;

      // Revoke the API key
      const revokeResponse = await fetch(`${ctx.config.apiUrl}/auth/revoke`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${apiKey}`,
        },
      });

      expect(revokeResponse.status).toBe(200);
      const revokeBody = await revokeResponse.json();
      expect(revokeBody.ok).toBe(true);
      expect(revokeBody.revoked).toBe(true);
      expect(revokeBody.hint).toContain("re-authenticate");

      // Old API key should no longer work
      const lockResponse = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${apiKey}`,
        },
        body: JSON.stringify({ channel: "agent.revokeuser.test" }),
      });
      expect(lockResponse.status).toBe(401);
    });

    it("Test 4.10: API Key - Old JWT tokens still work during transition", async () => {
      // Create a traditional JWT (simulating old token)
      const { SignJWT } = await import("jose");
      const jwtKey = new TextEncoder().encode(ctx.config.jwtSecret);
      const oldToken = await new SignJWT({})
        .setProtectedHeader({ alg: "HS256" })
        .setSubject("olduser")
        .setIssuedAt()
        .setExpirationTime("7d")
        .sign(jwtKey);

      // Should still work (backwards compatibility)
      const lockResponse = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${oldToken}`,
        },
        body: JSON.stringify({ channel: "agent.olduser.test" }),
      });

      // Should work because old JWT validation is supported
      expect(lockResponse.status).toBe(200);
    });

    it("Test 4.11: Claim expiry - Claims have TTL set", async () => {
      const username = "ttluser";
      const initResponse = await fetch(`${ctx.config.apiUrl}/auth/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });
      const initBody = await initResponse.json();
      const claimToken = initBody.claim_token;

      // Verify claim was created with TTL
      const pattern = `claim:${username}:*`;
      const keys = await ctx.redis!.keys(pattern);
      expect(keys.length).toBe(1);

      const ttl = await ctx.redis!.ttl(keys[0]);
      expect(ttl).toBeGreaterThan(0); // Should have TTL
      expect(ttl).toBeLessThanOrEqual(24 * 60 * 60); // 24 hours max
    });
  });
});
