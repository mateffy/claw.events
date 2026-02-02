import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "bun:test";
import {
  createTestContext,
  startTestServer,
  cleanupTestContext,
  clearTestData,
  createTestToken,
  type TestContext,
} from "./test-utils.ts";

describe("Profile and Locks Endpoints", () => {
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

  describe("GET /api/profile/:agent", () => {
    it("Test 18.1: GET /api/profile/:agent - Happy Path", async () => {
      const token = await createTestToken("alice", ctx.config.jwtSecret);

      // Create some advertisements for alice
      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
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

      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
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

      const response = await fetch(`${ctx.config.apiUrl}/api/profile/alice`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.agent).toBe("alice");
      expect(body.channels).toBeDefined();
      expect(body.channels.length).toBe(2);
      expect(body.count).toBe(2);
    });

    it("Test 18.2: GET /api/profile/:agent - Empty Profile", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/profile/newuser123`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.channels).toEqual([]);
      expect(body.count).toBe(0);
    });

    it("Test 18.3: GET /api/profile/:agent - Sorted by updatedAt", async () => {
      const token = await createTestToken("sortuser", ctx.config.jwtSecret);

      // Create ads with delays
      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
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

      await fetch(`${ctx.config.apiUrl}/api/advertise`, {
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

      const response = await fetch(`${ctx.config.apiUrl}/api/profile/sortuser`);

      const body = await response.json();
      // Should be sorted newest first
      expect(body.channels[0].channel).toBe("agent.sortuser.second");
      expect(body.channels[1].channel).toBe("agent.sortuser.first");
    });
  });

  describe("GET /api/locks/:agent", () => {
    it("Test 19.1: GET /api/locks/:agent - Happy Path", async () => {
      const token = await createTestToken("lockuser", ctx.config.jwtSecret);

      // Lock several channels
      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.lockuser.private1" }),
      });

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.lockuser.private2" }),
      });

      const response = await fetch(`${ctx.config.apiUrl}/api/locks/lockuser`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
      expect(body.agent).toBe("lockuser");
      expect(body.lockedChannels).toBeDefined();
      expect(body.lockedChannels.length).toBe(2);
      expect(body.count).toBe(2);
    });

    it("Test 19.2: GET /api/locks/:agent - No Locked Channels", async () => {
      const response = await fetch(`${ctx.config.apiUrl}/api/locks/newuser456`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.lockedChannels).toEqual([]);
      expect(body.count).toBe(0);
    });

    it("Test 19.3: GET /api/locks/:agent - Full Channel Names", async () => {
      const token = await createTestToken("fullname", ctx.config.jwtSecret);

      await fetch(`${ctx.config.apiUrl}/api/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ channel: "agent.fullname.test" }),
      });

      const response = await fetch(`${ctx.config.apiUrl}/api/locks/fullname`);

      const body = await response.json();
      expect(body.lockedChannels).toContain("agent.fullname.test");
    });
  });
});
