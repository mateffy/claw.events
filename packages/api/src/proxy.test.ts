import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "bun:test";
import {
  createTestContext,
  startTestServer,
  cleanupTestContext,
  clearTestData,
  createTestToken,
  mockFetch as createFetchMock,
  type TestContext,
} from "./test-utils.ts";

// Helper to mock Centrifugo API calls
const mockCentrifugo = () => {
  return createFetchMock((input: RequestInfo | URL, init?: RequestInit) => {
    const url = input.toString();
    if (url.includes("/api") && url.includes("800")) {
      return Promise.resolve(new Response(
        JSON.stringify({ result: { published: true } }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      ));
    }
    return Promise.resolve(new Response("Not found", { status: 404 }));
  });
};

describe("Proxy Endpoints (Centrifugo Integration)", () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext();
    await startTestServer(ctx);
  });

  afterAll(async () => {
    await cleanupTestContext(ctx);
  });

  beforeEach(async () => {
    if (ctx.redis) {
      await clearTestData(ctx.redis);
    }
  });

  afterEach(async () => {
    if (ctx.redis) {
      await clearTestData(ctx.redis);
    }
  });

  describe("POST /proxy/subscribe", () => {
    it("Test 4.1: POST /proxy/subscribe - Public Channel (public.*)", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
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
      const response = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "public.test", user: "" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
      expect(body.error).toBeUndefined();
    });

    it("Test 4.3: POST /proxy/subscribe - System Channel (system.*)", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "system.timer.minute", user: "anyone" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
      expect(body.error).toBeUndefined();
    });

    it("Test 4.4: POST /proxy/subscribe - Unlocked Agent Channel", async () => {
      // Create an unlocked agent channel (do not lock it)
      const response = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.updates", user: "bob" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
      expect(body.error).toBeUndefined();
    });

    it("Test 4.5: POST /proxy/subscribe - Unlocked Agent Channel Anonymous", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.updates", user: "" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
      expect(body.error).toBeUndefined();
    });

    it("Test 4.6: POST /proxy/subscribe - Locked Agent Channel Owner", async () => {
      // Lock the channel as alice
      const token = await createTestToken("alice", ctx.config.jwtSecret);
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      const response = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.private", user: "alice" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
      expect(body.error).toBeUndefined();
    });

    it("Test 4.7: POST /proxy/subscribe - Locked Agent Channel Granted User", async () => {
      // Lock and grant access as alice
      const token = await createTestToken("alice", ctx.config.jwtSecret);
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.private" }),
      });

      const response = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.private", user: "bob" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
      expect(body.error).toBeUndefined();
    });

    it("Test 4.8: POST /proxy/subscribe - Locked Agent Channel Non-Granted User", async () => {
      // Lock as alice
      const token = await createTestToken("alice", ctx.config.jwtSecret);
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      // Try to subscribe as charlie (not granted)
      const response = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
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
      const token = await createTestToken("alice", ctx.config.jwtSecret);
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      // Try to subscribe as anonymous
      const response = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
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
      const response = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
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
      const response = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
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
      const response = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.bob.test", user: "alice" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
      expect(body.error).toBeUndefined();
    });
  });

  describe("POST /proxy/publish", () => {
    it("Test 5.1: POST /proxy/publish - Public Channel Anyone", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "public.townsquare", user: "anyone" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
      expect(body.error).toBeUndefined();
    });

    it("Test 5.2: POST /proxy/publish - System Channel Denied", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
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
      const response = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.updates", user: "alice" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
      expect(body.error).toBeUndefined();
    });

    it("Test 5.4: POST /proxy/publish - Agent Channel Non-Owner", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
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
      const token = await createTestToken("alice", ctx.config.jwtSecret);
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      const response = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.private", user: "alice" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.result).toEqual({});
      expect(body.error).toBeUndefined();
    });

    it("Test 5.6: POST /proxy/publish - Locked Agent Channel Non-Owner Still Denied", async () => {
      // Lock and grant subscribe access to bob
      const token = await createTestToken("alice", ctx.config.jwtSecret);
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.private" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.private" }),
      });

      // Try to publish as bob
      const response = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
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
      const response = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
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
      const response = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
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

  /**
   * SECURITY MODEL TESTS
   * These tests verify the security pillars of the application.
   * They ensure that client_insecure mode doesn't compromise security.
   */
  describe("SECURITY PILLARS - Anonymous User Access (client_insecure mode)", () => {
    it("PILLAR 1: Anonymous users CAN read public.* channels", async () => {
      const subscribeResponse = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "public.events", user: "" }),
      });

      expect(subscribeResponse.status).toBe(200);
      const subBody = await subscribeResponse.json();
      expect(subBody.result).toEqual({});
      expect(subBody.error).toBeUndefined();
    });

    it("PILLAR 1: Anonymous users CAN read system.* channels", async () => {
      const subscribeResponse = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "system.broadcasts", user: "" }),
      });

      expect(subscribeResponse.status).toBe(200);
      const subBody = await subscribeResponse.json();
      expect(subBody.result).toEqual({});
      expect(subBody.error).toBeUndefined();
    });

    it("PILLAR 2: Anonymous users CANNOT subscribe to locked agent.* channels", async () => {
      // Lock channel as alice
      const token = await createTestToken("alice", ctx.config.jwtSecret);
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.secret" }),
      });

      // Anonymous user tries to subscribe
      const subscribeResponse = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.secret", user: "" }),
      });

      expect(subscribeResponse.status).toBe(200);
      const subBody = await subscribeResponse.json();
      expect(subBody.error).toBeDefined();
      expect(subBody.error.code).toBe(403);
    });

    it("PILLAR 2: Anonymous users CAN subscribe to unlocked agent.* channels", async () => {
      // Don't lock the channel - leave it unlocked
      const subscribeResponse = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.unlocked", user: "" }),
      });

      expect(subscribeResponse.status).toBe(200);
      const subBody = await subscribeResponse.json();
      expect(subBody.result).toEqual({});
      expect(subBody.error).toBeUndefined();
    });
  });

  describe("SECURITY PILLARS - Publishing Restrictions", () => {
    it("PILLAR 3: Anonymous users CAN publish to public.* channels", async () => {
      const publishResponse = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "public.chat", user: "" }),
      });

      expect(publishResponse.status).toBe(200);
      const pubBody = await publishResponse.json();
      expect(pubBody.result).toEqual({});
      expect(pubBody.error).toBeUndefined();
    });

    it("PILLAR 3: Anonymous users CANNOT publish to system.* channels", async () => {
      const publishResponse = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "system.announcements", user: "" }),
      });

      expect(publishResponse.status).toBe(200);
      const pubBody = await publishResponse.json();
      expect(pubBody.error).toBeDefined();
      expect(pubBody.error.code).toBe(403);
    });

    it("PILLAR 4: Only channel owner can publish to agent.* channels", async () => {
      // Owner publishes successfully
      const ownerResponse = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.data", user: "alice" }),
      });

      expect(ownerResponse.status).toBe(200);
      const ownerBody = await ownerResponse.json();
      expect(ownerBody.result).toEqual({});

      // Non-owner is denied
      const nonOwnerResponse = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.data", user: "bob" }),
      });

      expect(nonOwnerResponse.status).toBe(200);
      const nonOwnerBody = await nonOwnerResponse.json();
      expect(nonOwnerBody.error).toBeDefined();
      expect(nonOwnerBody.error.code).toBe(403);
    });

    it("PILLAR 4: Anonymous users CANNOT publish to agent.* channels", async () => {
      const publishResponse = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.data", user: "" }),
      });

      expect(publishResponse.status).toBe(200);
      const pubBody = await publishResponse.json();
      expect(pubBody.error).toBeDefined();
      expect(pubBody.error.code).toBe(403);
    });

    it("PILLAR 4: Granting subscribe access does NOT grant publish access", async () => {
      // Alice locks and grants bob subscribe access
      const token = await createTestToken("alice", ctx.config.jwtSecret);
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.alice.restricted" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.restricted" }),
      });

      // Bob CAN subscribe
      const subResponse = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.restricted", user: "bob" }),
      });

      expect(subResponse.status).toBe(200);
      const subBody = await subResponse.json();
      expect(subBody.result).toEqual({});

      // Bob CANNOT publish
      const pubResponse = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.restricted", user: "bob" }),
      });

      expect(pubResponse.status).toBe(200);
      const pubBody = await pubResponse.json();
      expect(pubBody.error).toBeDefined();
      expect(pubBody.error.code).toBe(403);
    });
  });

  describe("SECURITY PILLARS - Admin Actions Require Authentication", () => {
    it("PILLAR 5: Anonymous users CANNOT lock channels", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.test" }),
      });

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toBeDefined();
    });

    it("PILLAR 5: Anonymous users CANNOT unlock channels", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/unlock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.test" }),
      });

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toBeDefined();
    });

    it("PILLAR 5: Anonymous users CANNOT grant permissions", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.test" }),
      });

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toBeDefined();
    });

    it("PILLAR 5: Anonymous users CANNOT revoke permissions", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.test" }),
      });

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.error).toBeDefined();
    });

    it("PILLAR 5: Users CANNOT lock other users' channels", async () => {
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);
      
      // Bob tries to lock Alice's channel
      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.test" }),
      });

      expect(response.status).toBe(403);
      const body = await response.json();
    });

    it("PILLAR 5: Users can ONLY lock their own channels", async () => {
      const bobToken = await createTestToken("bob", ctx.config.jwtSecret);
      
      // Bob locks his own channel
      const response = await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${bobToken}`,
        },
        body: JSON.stringify({ channel: "agent.bob.private" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);

      // Verify the channel is actually locked
      const subResponse = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.bob.private", user: "alice" }),
      });

      expect(subResponse.status).toBe(200);
      const subBody = await subResponse.json();
      expect(subBody.error).toBeDefined();
      expect(subBody.error.code).toBe(403);
    });
  });

  describe("SECURITY PILLARS - Complete Access Matrix", () => {
    it("VERIFICATION: Public channel access matrix (anonymous user)", async () => {
      // Anonymous user can subscribe
      const subResponse = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "public.test", user: "" }),
      });
      const subBody = await subResponse.json();
      expect(subBody.result).toBeDefined();

      // Anonymous user can publish
      const pubResponse = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "public.test", user: "" }),
      });
      const pubBody = await pubResponse.json();
      expect(pubBody.result).toBeDefined();
    });

    it("VERIFICATION: System channel access matrix (anonymous user)", async () => {
      // Anonymous user can subscribe
      const subResponse = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "system.test", user: "" }),
      });
      const subBody = await subResponse.json();
      expect(subBody.result).toBeDefined();

      // Anonymous user CANNOT publish
      const pubResponse = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "system.test", user: "" }),
      });
      const pubBody = await pubResponse.json();
      expect(pubBody.error).toBeDefined();
      expect(pubBody.error.code).toBe(403);
    });

    it("VERIFICATION: Locked agent channel access matrix (granted user)", async () => {
      // Setup: Alice locks and grants Bob access
      const aliceToken = await createTestToken("alice", ctx.config.jwtSecret);
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ channel: "agent.alice.matrix" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/grant`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${aliceToken}`,
        },
        body: JSON.stringify({ target: "bob", channel: "agent.alice.matrix" }),
      });

      // Bob CAN subscribe
      const subResponse = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.matrix", user: "bob" }),
      });
      const subBody = await subResponse.json();
      expect(subBody.result).toBeDefined();

      // Bob CANNOT publish (subscribe access != publish access)
      const pubResponse = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.matrix", user: "bob" }),
      });
      const pubBody = await pubResponse.json();
      expect(pubBody.error).toBeDefined();
      expect(pubBody.error.code).toBe(403);

      // Alice CAN subscribe and publish
      const aliceSubResponse = await fetch(`${ctx.config.apiUrl}/proxy/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.matrix", user: "alice" }),
      });
      const aliceSubBody = await aliceSubResponse.json();
      expect(aliceSubBody.result).toBeDefined();

      const alicePubResponse = await fetch(`${ctx.config.apiUrl}/proxy/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "agent.alice.matrix", user: "alice" }),
      });
      const alicePubBody = await alicePubResponse.json();
      expect(alicePubBody.result).toBeDefined();
    });
  });
});
