import { describe, expect, test } from "bun:test";
import { AuthService } from "../src/auth_service.ts";
import {
  type AuthConfig,
  applyDatabaseUrl,
  createDefaultConfig,
  loadConfig,
} from "../src/config.ts";
import {
  base64UrlDecode,
  base64UrlEncode,
  createJwt,
  hashPassword,
  verifyJwt,
  verifyPassword,
} from "../src/crypto.ts";
import { SqliteDatabase } from "../src/database.ts";
import { createFetchHandler } from "../src/http_server.ts";

function makeTestConfig(): AuthConfig {
  return {
    ...createDefaultConfig(),
    dbDriver: "sqlite",
    dbPath: ":memory:",
    jwtSecret: "test-super-secret-key-at-least-32-bytes",
    accessTokenTtlSec: 900,
    refreshTokenTtlSec: 3600,
    pbkdf2Iterations: 10000,
    maxLoginAttempts: 3,
    rateLimitWindowSec: 60,
  };
}

describe("config env parsing", () => {
  test("parses DATABASE_URL and DB_* overrides", () => {
    const cfg = createDefaultConfig();
    applyDatabaseUrl(
      "mysql://smartuser:pass%40word@bayonos-db-smartfarm:3307/smartfarm_db?ssl-mode=PREFERRED",
      cfg,
    );
    expect(cfg.dbDriver).toBe("mysql");
    expect(cfg.mysqlUser).toBe("smartuser");
    expect(cfg.mysqlPassword).toBe("pass@word");
    expect(cfg.mysqlHost).toBe("bayonos-db-smartfarm");
    expect(cfg.mysqlPort).toBe(3307);
    expect(cfg.mysqlDatabase).toBe("smartfarm_db");

    const envCfg = loadConfig(
      {
        DB_CONNECTION: "mysql",
        DB_HOST: "db.internal",
        DB_PORT: "3308",
        DB_USERNAME: "appuser",
        DB_PASSWORD: "appsecret",
        DB_DATABASE: "smartfarm_db",
      },
      "",
    );
    expect(envCfg.dbDriver).toBe("mysql");
    expect(envCfg.mysqlHost).toBe("db.internal");
    expect(envCfg.mysqlPort).toBe(3308);
    expect(envCfg.mysqlUser).toBe("appuser");
    expect(envCfg.mysqlPassword).toBe("appsecret");
    expect(envCfg.mysqlDatabase).toBe("smartfarm_db");
  });
});

describe("crypto", () => {
  test("base64url, pbkdf2, and jwt sign/verify", async () => {
    const raw = "hello+world/test=123";
    const b64 = base64UrlEncode(raw);
    expect(base64UrlDecode(b64)).toBe(raw);

    const pwHash = await hashPassword("SecretPass123", 10000);
    expect(pwHash.startsWith("pbkdf2_sha256$10000$")).toBe(true);
    expect(await verifyPassword("SecretPass123", pwHash)).toBe(true);
    expect(await verifyPassword("WrongPass123", pwHash)).toBe(false);
    expect(await verifyPassword("SecretPass123", "malformed")).toBe(false);

    const now = AuthService.nowEpochSeconds();
    const token = createJwt(
      {
        userId: 42,
        username: "alice",
        email: "alice@example.com",
        role: "owner",
        issuedAt: now,
        expiresAt: now + 300,
        jti: "jti-1",
      },
      "secret-key",
    );

    const verified = verifyJwt(token, "secret-key", now);
    expect(verified).not.toBeNull();
    expect(verified?.userId).toBe(42);
    expect(verified?.username).toBe("alice");
    expect(verified?.email).toBe("alice@example.com");
    expect(verified?.role).toBe("owner");

    expect(verifyJwt(token, "wrong-secret", now)).toBeNull();
    expect(verifyJwt(token, "secret-key", now + 301)).toBeNull();

    const lastChar = token.at(-1);
    const tampered = token.slice(0, -1) + (lastChar === "a" ? "b" : "a");
    expect(verifyJwt(tampered, "secret-key", now)).toBeNull();
  });
});

describe("auth service", () => {
  test("register, login, refresh rotation, and logout", async () => {
    const cfg = makeTestConfig();
    const db = new SqliteDatabase(cfg.dbPath);
    await db.initSchema();
    const service = new AuthService(db, cfg);

    try {
      // Invalid inputs
      expect(
        (await service.registerUser("ab", "Password123", "Alice", "a@example.com")).statusCode,
      ).toBe(400);
      expect(
        (await service.registerUser("alice", "Password123", "", "a@example.com")).statusCode,
      ).toBe(400);
      expect(
        (await service.registerUser("alice", "Password123", "Alice", "bad-email")).statusCode,
      ).toBe(400);
      expect(
        (await service.registerUser("alice", "short1", "Alice", "alice@example.com")).statusCode,
      ).toBe(400);
      expect(
        (await service.registerUser("alice", "onlyletters", "Alice", "alice@example.com"))
          .statusCode,
      ).toBe(400);
      expect(
        (
          await service.registerUser(
            "alice",
            "Password123",
            "Alice",
            "alice@example.com",
            "",
            "invalidrole",
          )
        ).statusCode,
      ).toBe(400);

      // Valid registration
      const reg = await service.registerUser(
        "alice",
        "Password123",
        "Alice Chan",
        "Alice@Example.com",
        "010290240",
        "manager",
      );
      expect(reg.ok).toBe(true);
      expect(reg.statusCode).toBe(201);
      expect(reg.user?.email).toBe("alice@example.com");
      expect(reg.user?.full_name).toBe("Alice Chan");
      expect(reg.user?.phone).toBe("010290240");
      expect(reg.user?.role).toBe("manager");
      expect(reg.user?.status).toBe("active");
      expect(reg.tokens).toBeDefined();

      // Duplicate email / username
      expect(
        (await service.registerUser("alice2", "Password123", "Alice Two", "alice@example.com"))
          .statusCode,
      ).toBe(409);
      expect(
        (await service.registerUser("ALICE", "Password123", "Alice Dup", "alice2@example.com"))
          .statusCode,
      ).toBe(409);

      // Authenticate access token
      const claims = service.authenticateAccessToken(reg.tokens!.access_token);
      expect(claims).not.toBeNull();
      expect(claims?.userId).toBe(reg.user!.id);
      expect(claims?.role).toBe("manager");

      const profile = await service.getProfile(claims!.userId);
      expect(profile.ok).toBe(true);
      expect(profile.user?.username).toBe("alice");

      // Login by email and by username
      const loginEmail = await service.login("ALICE@example.com", "Password123", "127.0.0.1");
      expect(loginEmail.ok).toBe(true);
      expect(loginEmail.statusCode).toBe(200);

      const loginUser = await service.login("alice", "Password123", "127.0.0.2");
      expect(loginUser.ok).toBe(true);
      expect(loginUser.statusCode).toBe(200);

      // Wrong password
      const badLogin = await service.login("alice@example.com", "WrongPass123", "127.0.0.3");
      expect(badLogin.ok).toBe(false);
      expect(badLogin.statusCode).toBe(401);

      // Refresh token rotation
      const oldRefresh = loginEmail.tokens!.refresh_token;
      const refreshed = await service.refreshSession(oldRefresh);
      expect(refreshed.ok).toBe(true);
      expect(refreshed.statusCode).toBe(200);
      expect(refreshed.tokens?.refresh_token).not.toBe(oldRefresh);

      // Reusing old refresh token must fail
      const reuse = await service.refreshSession(oldRefresh);
      expect(reuse.ok).toBe(false);
      expect(reuse.statusCode).toBe(401);

      // Logout revokes new refresh token
      const out = await service.logout(refreshed.tokens!.refresh_token);
      expect(out.ok).toBe(true);
      expect((await service.refreshSession(refreshed.tokens!.refresh_token)).ok).toBe(false);
    } finally {
      await db.close();
    }
  });

  test("legacy plaintext passwords, rate limiting, and change password", async () => {
    const cfg = makeTestConfig();
    const db = new SqliteDatabase(cfg.dbPath);
    await db.initSchema();
    const service = new AuthService(db, cfg);

    try {
      const seeded = await db.createUser(
        "admin",
        "admin123",
        "Raksmey Chann",
        "admin@efarm.local",
        "010290240",
        "owner",
      );
      expect(seeded.user).toBeDefined();

      const loginSeed = await service.login("admin", "admin123", "10.0.0.1");
      expect(loginSeed.ok).toBe(true);
      expect(loginSeed.statusCode).toBe(200);
      expect(loginSeed.user?.full_name).toBe("Raksmey Chann");
      expect(loginSeed.user?.role).toBe("owner");

      // Rate limit threshold is 3 attempts per IP in test config
      expect((await service.login("admin", "Wrong1", "10.0.0.5")).statusCode).toBe(401);
      expect((await service.login("admin", "Wrong2", "10.0.0.5")).statusCode).toBe(401);
      expect((await service.login("admin", "Wrong3", "10.0.0.5")).statusCode).toBe(401);
      expect((await service.login("admin", "admin123", "10.0.0.5")).statusCode).toBe(429);

      // Change password revokes all existing refresh tokens
      const rt = loginSeed.tokens!.refresh_token;
      expect(
        (await service.changePassword(seeded.user!.id, "WrongCurrent1", "NewPass123")).statusCode,
      ).toBe(401);
      const changed = await service.changePassword(seeded.user!.id, "admin123", "NewPass123");
      expect(changed.ok).toBe(true);
      expect(changed.statusCode).toBe(200);

      expect((await service.refreshSession(rt)).ok).toBe(false);
      expect((await service.login("admin", "admin123", "10.0.0.6")).statusCode).toBe(401);
      expect((await service.login("admin", "NewPass123", "10.0.0.6")).statusCode).toBe(200);
    } finally {
      await db.close();
    }
  });
});

describe("http routes", () => {
  test("all endpoints, aliases, CORS, and auth flows", async () => {
    const cfg = makeTestConfig();
    const db = new SqliteDatabase(cfg.dbPath);
    await db.initSchema();
    const service = new AuthService(db, cfg);
    const handler = createFetchHandler(service);

    const dispatch = async (
      method: string,
      path: string,
      body?: string,
      authHeader?: string,
    ) => {
      const headers: Record<string, string> = {};
      if (body !== undefined) {
        headers["Content-Type"] = "application/json";
      }
      if (authHeader) {
        headers["Authorization"] = authHeader;
      }
      const req = new Request(`http://localhost${path}`, {
        method,
        headers,
        body,
      });
      return handler(req);
    };

    try {
      // CORS preflight
      const preflight = await dispatch("OPTIONS", "/api/auth/login");
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get("Access-Control-Allow-Origin")).toBe("*");

      // Root and Health
      const root = await dispatch("GET", "/");
      expect(root.status).toBe(200);
      expect(((await root.json()) as { status: string }).status).toBe("ok");

      const health = await dispatch("GET", "/health");
      expect(health.status).toBe(200);
      expect(((await health.json()) as { status: string }).status).toBe("ok");

      // Invalid JSON -> 400
      const badJson = await dispatch("POST", "/api/auth/register", "{bad");
      expect(badJson.status).toBe(400);

      // Register
      const reg = await dispatch(
        "POST",
        "/api/auth/register",
        JSON.stringify({
          username: "httpuser",
          password: "Password123",
          full_name: "HTTP User",
          email: "http@example.com",
          phone: "012345678",
          role: "staff",
        }),
      );
      expect(reg.status).toBe(201);
      const regJson = (await reg.json()) as {
        access_token: string;
        refresh_token: string;
        user: { full_name: string; role: string };
      };
      expect(regJson.access_token).toBeTruthy();
      expect(regJson.refresh_token).toBeTruthy();
      expect(regJson.user.full_name).toBe("HTTP User");
      expect(regJson.user.role).toBe("staff");

      // Login (including /auth/login alias)
      const loginAlias = await dispatch(
        "POST",
        "/auth/login",
        JSON.stringify({ email: "http@example.com", password: "Password123" }),
      );
      expect(loginAlias.status).toBe(200);

      const login = await dispatch(
        "POST",
        "/api/auth/login",
        JSON.stringify({ email: "http@example.com", password: "Password123" }),
      );
      expect(login.status).toBe(200);
      const loginJson = (await login.json()) as {
        access_token: string;
        refresh_token: string;
      };

      // Protected /me without header -> 401
      const meUnauth = await dispatch("GET", "/api/auth/me");
      expect(meUnauth.status).toBe(401);

      // Protected /me with Bearer token -> 200
      const me = await dispatch(
        "GET",
        "/api/auth/me",
        undefined,
        `Bearer ${loginJson.access_token}`,
      );
      expect(me.status).toBe(200);
      const meJson = (await me.json()) as { user: { username: string } };
      expect(meJson.user.username).toBe("httpuser");

      // Refresh
      const ref = await dispatch(
        "POST",
        "/api/auth/refresh",
        JSON.stringify({ refresh_token: loginJson.refresh_token }),
      );
      expect(ref.status).toBe(200);
      const refJson = (await ref.json()) as { refresh_token: string };
      expect(refJson.refresh_token).not.toBe(loginJson.refresh_token);

      // Change password
      const cp = await dispatch(
        "POST",
        "/api/auth/change-password",
        JSON.stringify({
          current_password: "Password123",
          new_password: "NewPassword456",
        }),
        `Bearer ${loginJson.access_token}`,
      );
      expect(cp.status).toBe(200);

      // Refresh token revoked by password change -> 401
      const refAfterCp = await dispatch(
        "POST",
        "/api/auth/refresh",
        JSON.stringify({ refresh_token: refJson.refresh_token }),
      );
      expect(refAfterCp.status).toBe(401);

      // Login with new password & logout-all
      const login2 = await dispatch(
        "POST",
        "/api/auth/login",
        JSON.stringify({ username: "httpuser", password: "NewPassword456" }),
      );
      expect(login2.status).toBe(200);
      const login2Json = (await login2.json()) as {
        access_token: string;
        refresh_token: string;
      };

      const logoutAll = await dispatch(
        "POST",
        "/api/auth/logout-all",
        undefined,
        `Bearer ${login2Json.access_token}`,
      );
      expect(logoutAll.status).toBe(200);

      const refAfterLogoutAll = await dispatch(
        "POST",
        "/api/auth/refresh",
        JSON.stringify({ refresh_token: login2Json.refresh_token }),
      );
      expect(refAfterLogoutAll.status).toBe(401);
    } finally {
      await db.close();
    }
  });
});
