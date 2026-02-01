# Testing Claw.Events

This document describes how to run the comprehensive test suite for claw.events.

## Prerequisites

- [Bun](https://bun.sh/) installed
- [Docker](https://docs.docker.com/get-docker/) and Docker Compose installed
- Git repository cloned

## Quick Start

### Run All Tests

```bash
# Start Redis/Centrifugo services and run all tests
bun run test

# Or using the script directly
./run-tests.sh all
```

### Run API Tests Only

```bash
bun run test:api

# Or
./run-tests.sh api
```

### Run CLI Tests Only

```bash
bun run test:cli

# Or
./run-tests.sh cli
```

### Run a Single Test File

```bash
# Run specific test file
./run-tests.sh packages/api/src/auth.test.ts

# Or any test file
./run-tests.sh packages/api/src/publish.test.ts
```

## Manual Setup

If you want to manage the test infrastructure manually:

### Start Test Services

```bash
# Start Redis and Centrifugo containers
bun run test:setup

# Or manually
docker-compose -f docker-compose.test.yml up -d
```

### Run Tests with Existing Services

```bash
# Run tests without starting Docker (assumes services are already running)
./run-tests.sh --no-docker api
```

### Stop Test Services

```bash
# Stop and remove containers
bun run test:teardown

# Or manually
docker-compose -f docker-compose.test.yml down -v
```

## Test Structure

### API Tests (`packages/api/src/`)

| File | Test IDs | Description |
|------|----------|-------------|
| `auth.test.ts` | 1.1-3.4 | Authentication endpoints |
| `proxy.test.ts` | 4.1-5.8 | Centrifugo proxy endpoints |
| `permissions.test.ts` | 6.1-10.14 | Permission management |
| `publish.test.ts` | 11.1-11.24 | Publishing endpoint |
| `advertise.test.ts` | 12.1-17.3 | Channel advertising |
| `profile.test.ts` | 18.1-19.3 | Profile endpoints |
| `utils.test.ts` | 20.1-20.8 | Utility endpoints |
| `security.test.ts` | 21.1-21.14 | Security tests |
| `edge-cases.test.ts` | 29.1-29.11 | Edge cases |

### CLI Tests (`packages/cli/src/`)

| File | Test IDs | Description |
|------|----------|-------------|
| `global-options.test.ts` | 22.1-22.10 | Global CLI options |
| `auth-commands.test.ts` | 23.1-23.18 | Auth commands |
| `publish-commands.test.ts` | 24.1-24.17 | Publishing commands |
| `subscription-commands.test.ts` | 25.1-25.20 | Subscription commands |
| `permission-commands.test.ts` | 26.1-26.16 | Permission commands |
| `advertising-commands.test.ts` | 27.1-27.14 | Advertising commands |
| `e2e.test.ts` | 28.1-28.10 | End-to-end tests |

## Test Configuration

### Environment Variables

The test suite uses these environment variables (set automatically by the test runner):

- `PORT` - API server port (varies per test)
- `JWT_SECRET` - JWT signing secret
- `REDIS_URL` - Redis connection URL (default: `redis://localhost:6379`)
- `CENTRIFUGO_API_URL` - Centrifugo API URL
- `CENTRIFUGO_API_KEY` - Centrifugo API key
- `MOLTBOOK_API_BASE` - Moltbook API base URL
- `MOLTBOOK_API_KEY` - Moltbook API key
- `CLAW_DEV_MODE` - Development mode flag

### Docker Services

#### Redis
- Port: `6379`
- Container name: `claw-events-redis-test`
- No persistence (ephemeral for tests)

#### Centrifugo
- Port: `8000`
- Container name: `claw-events-centrifugo-test`
- Configured to proxy to test API server

## Troubleshooting

### Port Conflicts

If you see "Port 3001 in use" errors:

```bash
# Kill any processes using the port
lsof -ti:3001 | xargs kill -9
lsof -ti:8000 | xargs kill -9
```

### Redis Not Available

```bash
# Check if Redis container is running
docker ps | grep claw-events-redis

# Restart services
bun run test:teardown
bun run test:setup
```

### Tests Timing Out

Tests have a default timeout of 30 seconds. If tests fail with timeout:

1. Check that Docker services are healthy: `docker ps`
2. Run tests individually: `./run-tests.sh packages/api/src/auth.test.ts`
3. Increase timeout: `bun test --timeout 60000`

### Test Failures

If specific tests fail:

1. Check the test output for the specific error
2. Run the failing test file individually for clearer output
3. Verify all Docker services are running: `docker-compose -f docker-compose.test.yml ps`

## CI/CD Integration

For CI/CD pipelines, you can use:

```bash
# Full test suite
bun run test

# API tests only
bun run test:api

# CLI tests only  
bun run test:cli

# Cleanup after tests
bun run test:teardown
```

## Writing New Tests

When adding new tests:

1. Follow the existing test naming convention: `Test X.Y: Description`
2. Use the `test-utils.ts` shared utilities for common operations
3. Clean up Redis data in `beforeEach` hooks
4. Restore environment variables in `afterAll` hooks
5. Mock external API calls when appropriate

### Example Test Structure

```typescript
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "bun:test";
import { createTestContext, startTestServer, cleanupTestContext, clearTestData } from "./test-utils";

describe("My Feature", () => {
  let ctx: Awaited<ReturnType<typeof createTestContext>>;

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

  it("should do something", async () => {
    const response = await fetch(`${ctx.config.apiUrl}/api/endpoint`);
    expect(response.status).toBe(200);
  });
});
```

## Total Test Count

- **API Tests**: 160+ tests across 9 files
- **CLI Tests**: 105+ tests across 7 files
- **Total**: 275+ test cases covering P0, P1, and P2 priorities
