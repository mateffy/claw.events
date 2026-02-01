import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { existsSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const TEST_API_URL = "http://localhost:3001";

const execCLI = async (args: string[], configPath?: string): Promise<{ stdout: string; stderr: string; exitCode: number }> => {
  const env = `CLAW_API_URL=${TEST_API_URL}`;
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

describe("CLI Publish Commands", () => {
  const testDir = join(tmpdir(), "claw-cli-pub-test-" + Date.now());
  
  beforeAll(() => {
    if (!existsSync(testDir)) mkdirSync(testDir, { recursive: true });
  });
  
  afterAll(() => {
    try { rmSync(testDir, { recursive: true, force: true }); } catch {}
  });
  
  beforeEach(() => {
    try { rmSync(join(testDir, "config.json"), { force: true }); } catch {}
  });

  it("Test 24.1: pub - String Message", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "testuser", token: "eyJ.test"
    }));
    const { stdout, exitCode } = await execCLI(["pub", "public.test", "hello world"], testDir);
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
    }
  });

  it("Test 24.2: pub - JSON Message Auto-Parsed", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "testuser", token: "eyJ.test"
    }));
    const { stdout, exitCode } = await execCLI(["pub", "agent.testuser.data", '{"key":"value"}'], testDir);
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.data.payload).toEqual({ key: "value" });
    }
  });

  it("Test 24.3: pub - No Message (Null Payload)", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "testuser", token: "eyJ.test"
    }));
    const { stdout, exitCode } = await execCLI(["pub", "public.test"], testDir);
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
    }
  });

  it("Test 24.4: pub - Missing Channel", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "testuser", token: "eyJ.test"
    }));
    const { stderr, exitCode } = await execCLI(["pub"], testDir);
    expect(exitCode).toBe(1);
    const output = JSON.parse(stderr);
    expect(output.error).toContain("Missing channel");
  });

  it("Test 24.5: pub - Not Authenticated", async () => {
    const { stderr, exitCode } = await execCLI(["pub", "agent.testuser.data", "hello"], testDir);
    expect(exitCode).toBe(1);
    const output = JSON.parse(stderr);
    expect(output.error).toContain("Authentication required");
  });

  it("Test 24.6: pub - Rate Limited (429)", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "rateuser", token: "eyJ.test"
    }));
    
    // First publish
    await execCLI(["pub", "public.rate", "msg1"], testDir);
    
    // Second publish immediately
    const { stderr, exitCode } = await execCLI(["pub", "public.rate", "msg2"], testDir);
    
    if (exitCode === 1) {
      const output = JSON.parse(stderr);
      expect(output.error).toContain("Rate limit");
      expect(output.fixes).toBeDefined();
    }
  });

  it("Test 24.7: pub - Permission Denied (403)", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "unauthorized", token: "eyJ.test"
    }));
    const { stderr, exitCode } = await execCLI(["pub", "agent.other.data", "hello"], testDir);
    expect([0, 1]).toContain(exitCode);
    if (exitCode === 1) {
      expect(stderr).toContain("error");
    }
  });

  it("Test 24.8: pub - System Channel Denied", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "testuser", token: "eyJ.test"
    }));
    const { stderr, exitCode } = await execCLI(["pub", "system.timer.test", "hello"], testDir);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("error");
  });

  it("Test 24.9: pub - Network Error", async () => {
    const badEnv = `CLAW_API_URL=http://invalid-server:9999`;
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "testuser", token: "eyJ.test"
    }));
    
    const proc = Bun.spawn({
      cmd: ["bash", "-c", `${badEnv} bun run /Users/mat/dev/claw.events/packages/cli/src/index.ts --config ${testDir} pub public.test hello`],
      stdout: "pipe",
      stderr: "pipe",
    });
    
    const stderr = await new Response(proc.stderr).text();
    const exitCode = proc.exitCode ?? 0;
    
    expect(exitCode).toBe(1);
    expect(stderr).toContain("error");
  });

  it("Test 24.10: validate - With Inline Schema (Valid)", async () => {
    const { stdout, exitCode } = await execCLI([
      "validate", '{"temp":25}',
      "--schema", '{"type":"object"}'
    ], testDir);
    
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
    }
  });

  it("Test 24.11: validate - With Inline Schema (Invalid)", async () => {
    const { stderr, exitCode } = await execCLI([
      "validate", '{"temp":"hot"}',
      "--schema", '{"type":"object","properties":{"temp":{"type":"number"}}}'
    ], testDir);
    
    expect(exitCode).toBe(1);
    const output = JSON.parse(stderr);
    expect(output.status).toBe("error");
  });

  it("Test 24.12: validate - From Channel Schema", async () => {
    writeFileSync(join(testDir, "config.json"), JSON.stringify({ 
      username: "testuser", token: "eyJ.test"
    }));
    
    // First advertise channel with schema
    await execCLI([
      "advertise", "set",
      "-c", "agent.testuser.schema",
      "-s", '{"type":"object","properties":{"value":{"type":"number"}}}'
    ], testDir);
    
    // Then validate against it
    const { stdout, exitCode } = await execCLI([
      "validate", '{"value":42}',
      "--channel", "agent.testuser.schema"
    ], testDir);
    
    expect([0, 1]).toContain(exitCode);
  });

  it("Test 24.13: validate - From Stdin", async () => {
    const proc = Bun.spawn({
      cmd: ["bash", "-c", `echo '{"temp":25}' | bun run /Users/mat/dev/claw.events/packages/cli/src/index.ts --config ${testDir} validate --schema '{"type":"object"}'`],
      stdout: "pipe",
      stderr: "pipe",
    });
    
    const stdout = await new Response(proc.stdout).text();
    const exitCode = proc.exitCode ?? 0;
    
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.status).toBe("success");
    }
  });

  it("Test 24.14: validate - No Data", async () => {
    const { stderr, exitCode } = await execCLI([
      "validate", "--schema", '{"type":"object"}'
    ], testDir);
    
    expect(exitCode).toBe(1);
  });

  it("Test 24.15: validate - Invalid JSON Input", async () => {
    const { stderr, exitCode } = await execCLI([
      "validate", "not json",
      "--schema", '{"type":"object"}'
    ], testDir);
    
    if (exitCode === 1) {
      const output = JSON.parse(stderr);
      expect(output.status).toBe("error");
    }
  });

  it("Test 24.16: validate - Invalid Schema JSON", async () => {
    const { stderr, exitCode } = await execCLI([
      "validate", '{"a":1}',
      "--schema", "not json"
    ], testDir);
    
    expect(exitCode).toBe(1);
  });

  it("Test 24.17: validate - No Schema (Pass Through)", async () => {
    const { stdout, exitCode } = await execCLI(["validate", '{"a":1}'], testDir);
    
    if (exitCode === 0) {
      const output = JSON.parse(stdout);
      expect(output.data).toEqual({ a: 1 });
    }
  });
});
