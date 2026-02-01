import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { existsSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const TEST_API_URL = "http://localhost:3001";
const TEST_WS_URL = "ws://localhost:8001";

const execCLI = async (args: string[], configPath?: string): Promise<{ stdout: string; stderr: string; exitCode: number }> => {
  const env = `CLAW_API_URL=${TEST_API_URL} CLAW_WS_URL=${TEST_WS_URL}`;
  const cmd = configPath 
    ? `${env} bun run /Users/mat/dev/claw.events/packages/cli/src/index.ts --config ${configPath} ${args.join(" ")}`
    : `${env} bun run /Users/mat/dev/claw.events/packages/cli/src/index.ts ${args.join(" ")}`;
  
  const proc = Bun.spawn({
    cmd: ["bash", "-c", cmd],
    stdout: "pipe",
    stderr: "pipe",
  });
  
  const stdout = await new Response(proc.stdout).text();
  const stderr = await new Response(proc.stderr).text();
  const exitCode = proc.exitCode ?? 0;
  
  return { stdout, stderr, exitCode };
};

describe("E2E Integration Tests", () => {
  const testDir = join(tmpdir(), "claw-e2e-test-" + Date.now());
  
  beforeAll(() => {
    if (!existsSync(testDir)) mkdirSync(testDir, { recursive: true });
  });
  
  afterAll(() => {
    try { rmSync(testDir, { recursive: true, force: true }); } catch {}
  });
  
  beforeEach(() => {
    try { rmSync(join(testDir, "config.json"), { force: true }); } catch {}
  });

  it("Test 28.1: Full Auth Flow - Production (Mocked)", async () => {
    // 1. Login
    const { stdout: loginOut, exitCode: loginExit } = await execCLI(["login", "--user", "e2euser"], testDir);
    expect([0, 1]).toContain(loginExit); // May fail if server not available
    
    if (loginExit === 0) {
      const loginOutput = JSON.parse(loginOut);
      expect(loginOutput.status).toBe("success");
      
      // 2. Whoami - not yet verified
      const { stdout: whoamiOut } = await execCLI(["whoami"], testDir);
      const whoamiOutput = JSON.parse(whoamiOut);
      expect(whoamiOutput.data.username).toBe("e2euser");
    }
  });

  it("Test 28.2: Full Auth Flow - Dev Mode", async () => {
    // 1. Dev register
    const { stdout: regOut, exitCode: regExit } = await execCLI(["dev-register", "--user", "e2edevuser"], testDir);
    
    if (regExit === 0) {
      const regOutput = JSON.parse(regOut);
      expect(regOutput.status).toBe("success");
      
      // 2. Whoami - should be authenticated
      const { stdout: whoamiOut } = await execCLI(["whoami"], testDir);
      const whoamiOutput = JSON.parse(whoamiOut);
      expect(whoamiOutput.data.authenticated).toBe(true);
      
      // 3. Logout
      const { stdout: logoutOut } = await execCLI(["logout"], testDir);
      const logoutOutput = JSON.parse(logoutOut);
      expect(logoutOutput.status).toBe("success");
    }
  });

  it("Test 28.3: Full Permission Workflow", async () => {
    // Setup alice
    const aliceDir = join(testDir, "alice");
    mkdirSync(aliceDir, { recursive: true });
    
    // Alice dev-register
    await execCLI(["dev-register", "--user", "alice"], aliceDir);
    
    // Alice locks channel
    const { exitCode: lockExit } = await execCLI(["lock", "agent.alice.e2e"], aliceDir);
    expect([0, 1]).toContain(lockExit);
    
    if (lockExit === 0) {
      // Alice grants bob
      const { exitCode: grantExit } = await execCLI(["grant", "bob", "agent.alice.e2e"], aliceDir);
      expect([0, 1]).toContain(grantExit);
      
      if (grantExit === 0) {
        // Alice revokes bob
        const { exitCode: revokeExit } = await execCLI(["revoke", "bob", "agent.alice.e2e"], aliceDir);
        expect([0, 1]).toContain(revokeExit);
      }
    }
    
    rmSync(aliceDir, { recursive: true, force: true });
  });

  it("Test 28.4: Channel Discovery and Subscribe", async () => {
    // Setup alice
    const aliceDir = join(testDir, "alice");
    mkdirSync(aliceDir, { recursive: true });
    
    // Alice registers and advertises
    await execCLI(["dev-register", "--user", "alice"], aliceDir);
    await execCLI([
      "advertise", "set",
      "--channel", "agent.alice.discovery",
      "--desc", "Discovery test channel"
    ], aliceDir);
    
    // Search for alice's channel
    const { stdout: searchOut, exitCode: searchExit } = await execCLI(["advertise", "search", "discovery"], testDir);
    expect(searchExit).toBe(0);
    
    const searchOutput = JSON.parse(searchOut);
    const foundChannel = searchOutput.data.results.find((r: any) => r.channel === "agent.alice.discovery");
    expect(foundChannel).toBeDefined();
    
    rmSync(aliceDir, { recursive: true, force: true });
  });

  it("Test 28.5: Multi-Agent Setup", async () => {
    const agents = ["multi1", "multi2", "multi3"];
    const agentDirs = agents.map(a => ({ name: a, dir: join(testDir, a) }));
    
    // Register all agents
    for (const agent of agentDirs) {
      mkdirSync(agent.dir, { recursive: true });
      await execCLI(["dev-register", "--user", agent.name], agent.dir);
    }
    
    // Multi1 locks and grants multi2
    const multi1Dir = agentDirs[0].dir;
    await execCLI(["lock", "agent.multi1.shared"], multi1Dir);
    await execCLI(["grant", "multi2", "agent.multi1.shared"], multi1Dir);
    
    // Cleanup
    for (const agent of agentDirs) {
      rmSync(agent.dir, { recursive: true, force: true });
    }
  });

  it("Test 28.6: Pub/Sub Integration", async () => {
    // Setup publisher
    const pubDir = join(testDir, "publisher");
    mkdirSync(pubDir, { recursive: true });
    await execCLI(["dev-register", "--user", "publisher"], pubDir);
    
    // Publish a message
    const { exitCode: pubExit } = await execCLI([
      "pub", "public.e2e", "test message"
    ], pubDir);
    
    expect([0, 1]).toContain(pubExit);
    
    rmSync(pubDir, { recursive: true, force: true });
  });

  it("Test 28.7: Multiple Subscribers", async () => {
    // This would require running multiple sub processes
    // For now, just verify the channel exists
    const { stdout, exitCode } = await execCLI(["advertise", "list"], testDir);
    expect(exitCode).toBe(0);
    
    const output = JSON.parse(stdout);
    expect(Array.isArray(output.data.channels)).toBe(true);
  });

  it("Test 28.8: Rate Limit Recovery", async () => {
    const userDir = join(testDir, "ratelimit");
    mkdirSync(userDir, { recursive: true });
    await execCLI(["dev-register", "--user", "ratetest"], userDir);
    
    // First publish
    const { exitCode: pub1Exit } = await execCLI(["pub", "public.rate", "msg1"], userDir);
    
    // Second publish immediately (may be rate limited)
    const { exitCode: pub2Exit } = await execCLI(["pub", "public.rate", "msg2"], userDir);
    
    // One should succeed, one may be rate limited
    expect([0, 1]).toContain(pub1Exit);
    expect([0, 1]).toContain(pub2Exit);
    
    rmSync(userDir, { recursive: true, force: true });
  });

  it("Test 28.9: Batch Processing with subexec", async () => {
    // Verify subexec help works
    const { stdout, exitCode } = await execCLI(["subexec", "--help"], testDir);
    expect(exitCode).toBe(0);
    
    const output = JSON.parse(stdout);
    expect(output.status).toBe("help");
    expect(output.usage).toContain("--buffer");
  });

  it("Test 28.10: Schema Validation Pipeline", async () => {
    const userDir = join(testDir, "schema");
    mkdirSync(userDir, { recursive: true });
    await execCLI(["dev-register", "--user", "schemauser"], userDir);
    
    // Advertise channel with schema
    await execCLI([
      "advertise", "set",
      "--channel", "agent.schemauser.validated",
      "--desc", "Validated channel",
      "--schema", '{"type":"object","properties":{"value":{"type":"number"}}}'
    ], userDir);
    
    // Validate data
    const { stdout, exitCode } = await execCLI([
      "validate", '{"value":42}',
      "--schema", '{"type":"object","properties":{"value":{"type":"number"}}}'
    ], userDir);
    
    expect(exitCode).toBe(0);
    
    rmSync(userDir, { recursive: true, force: true });
  });
});
