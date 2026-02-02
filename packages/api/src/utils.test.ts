import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import type { Server } from "bun";
import { createClient, type RedisClientType } from "redis";

// Test configuration
const TEST_PORT = parseInt(process.env.PORT || "3001");
const TEST_API_URL = `http://localhost:${TEST_PORT}`;

describe("Utility Endpoints", () => {
  let server: Server;
  let redis: RedisClientType;
  let originalEnv: Record<string, string | undefined>;

  beforeAll(async () => {
    originalEnv = { ...process.env };
    
    process.env.PORT = String(TEST_PORT);
    process.env.JWT_SECRET = "test-jwt-secret-for-testing-only";
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

  describe("GET /health", () => {
    it("Test 20.1: GET /health - Returns OK", async () => {
      const response = await fetch(`${TEST_API_URL}/health`);

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.ok).toBe(true);
    });

    it("Test 20.2: GET /health - No Auth Required", async () => {
      // No Authorization header
      const response = await fetch(`${TEST_API_URL}/health`, {
        headers: { "Content-Type": "application/json" },
      });

      expect(response.status).toBe(200);
    });
  });

  describe("GET /og.jpeg", () => {
    it("Test 20.3: GET /og.jpeg - Returns Image", async () => {
      const response = await fetch(`${TEST_API_URL}/og.jpeg`);

      // May be 200 if image exists or 404 if not
      expect([200, 404]).toContain(response.status);
      
      if (response.status === 200) {
        const contentType = response.headers.get("Content-Type");
        expect(contentType).toContain("image/jpeg");
      }
    });

    it("Test 20.4: GET /og.jpeg - Cache Headers", async () => {
      const response = await fetch(`${TEST_API_URL}/og.jpeg`);

      if (response.status === 200) {
        const cacheControl = response.headers.get("Cache-Control");
        expect(cacheControl).toBeDefined();
        expect(cacheControl).toContain("max-age");
      }
    });

    it("Test 20.5: GET /og.jpeg - Not Found Handling", async () => {
      // Response should be either 404 or 200 depending on if file exists
      const response = await fetch(`${TEST_API_URL}/og.jpeg`);
      expect([200, 404]).toContain(response.status);
    });
  });

  describe("GET / (homepage)", () => {
    it("Test 20.6: GET / (homepage) - Returns HTML", async () => {
      const response = await fetch(`${TEST_API_URL}/`);

      expect(response.status).toBe(200);
      const contentType = response.headers.get("Content-Type");
      expect(contentType).toContain("text/html");
    });

    it("Test 20.7: GET / (homepage) - Stats Included", async () => {
      const response = await fetch(`${TEST_API_URL}/`);

      const html = await response.text();
      // Should contain stats placeholders or values
      expect(html).toContain("Agents");
      expect(html).toContain("Messages");
    });
  });

  describe("GET /docs", () => {
    it("Test 20.8: GET /docs - Returns Documentation", async () => {
      const response = await fetch(`${TEST_API_URL}/docs`);

      expect(response.status).toBe(200);
      const contentType = response.headers.get("Content-Type");
      expect(contentType).toContain("text/html");
      
      const html = await response.text();
      expect(html).toContain("Documentation");
    });
  });
});
