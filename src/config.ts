import { existsSync, readFileSync } from "node:fs";
import { randomHex } from "./crypto.ts";

export interface AuthConfig {
  host: string;
  port: number;

  // Database backend: "mysql" (default) or "sqlite"
  dbDriver: string;
  dbPath: string; // Used when dbDriver === "sqlite"

  mysqlHost: string;
  mysqlPort: number;
  mysqlUser: string;
  mysqlPassword: string;
  mysqlDatabase: string;

  jwtSecret: string;
  jwtSecretIsEphemeral: boolean;
  accessTokenTtlSec: number;
  refreshTokenTtlSec: number;
  pbkdf2Iterations: number;
  maxLoginAttempts: number;
  rateLimitWindowSec: number;
}

export function createDefaultConfig(): AuthConfig {
  return {
    host: "0.0.0.0",
    port: 8080,
    dbDriver: "mysql",
    dbPath: "auth.db",
    mysqlHost: "127.0.0.1",
    mysqlPort: 3306,
    mysqlUser: "root",
    mysqlPassword: "root",
    mysqlDatabase: "smartfarm_db",
    jwtSecret: "",
    jwtSecretIsEphemeral: false,
    accessTokenTtlSec: 900,
    refreshTokenTtlSec: 604800,
    pbkdf2Iterations: 210000,
    maxLoginAttempts: 10,
    rateLimitWindowSec: 60,
  };
}

function loadDotEnvIfPresent(
  path: string,
  targetEnv: Record<string, string | undefined>,
): void {
  if (!existsSync(path)) {
    return;
  }
  const content = readFileSync(path, "utf8");
  for (const rawLine of content.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) {
      continue;
    }
    const key = trimmed.slice(0, eqIndex).trim();
    let val = trimmed.slice(eqIndex + 1).trim();
    if (
      val.length >= 2 &&
      ((val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'")))
    ) {
      val = val.slice(1, -1);
    }
    // Process/container environment variables take precedence over .env
    if (key && targetEnv[key] === undefined) {
      targetEnv[key] = val;
    }
  }
}

function safeDecodeURIComponent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export function applyDatabaseUrl(url: string, cfg: AuthConfig): void {
  if (!url) {
    return;
  }
  const schemeEnd = url.indexOf("://");
  if (schemeEnd === -1) {
    return;
  }
  const scheme = url.slice(0, schemeEnd).toLowerCase();
  let rest = url.slice(schemeEnd + 3);

  if (scheme === "sqlite" || scheme === "sqlite3") {
    cfg.dbDriver = "sqlite";
    if (rest) {
      cfg.dbPath = rest;
    }
    return;
  }

  if (scheme !== "mysql" && scheme !== "mysql2" && scheme !== "mariadb") {
    return;
  }
  cfg.dbDriver = "mysql";

  // Strip optional query string (?ssl-mode=...)
  const qPos = rest.indexOf("?");
  if (qPos !== -1) {
    rest = rest.slice(0, qPos);
  }

  let authority = rest;
  const slashPos = rest.indexOf("/");
  if (slashPos !== -1) {
    authority = rest.slice(0, slashPos);
    const dbName = rest.slice(slashPos + 1);
    if (dbName) {
      cfg.mysqlDatabase = safeDecodeURIComponent(dbName);
    }
  }

  let hostPort = authority;
  const atPos = authority.lastIndexOf("@");
  if (atPos !== -1) {
    const userinfo = authority.slice(0, atPos);
    hostPort = authority.slice(atPos + 1);
    const colonPos = userinfo.indexOf(":");
    if (colonPos !== -1) {
      cfg.mysqlUser = safeDecodeURIComponent(userinfo.slice(0, colonPos));
      cfg.mysqlPassword = safeDecodeURIComponent(userinfo.slice(colonPos + 1));
    } else if (userinfo) {
      cfg.mysqlUser = safeDecodeURIComponent(userinfo);
    }
  }

  if (hostPort) {
    const colonPos = hostPort.lastIndexOf(":");
    if (colonPos !== -1) {
      const hostPart = hostPort.slice(0, colonPos);
      const portPart = hostPort.slice(colonPos + 1);
      if (hostPart) {
        cfg.mysqlHost = hostPart;
      }
      const parsed = Number.parseInt(portPart, 10);
      if (Number.isInteger(parsed) && parsed > 0 && parsed <= 65535) {
        cfg.mysqlPort = parsed;
      }
    } else {
      cfg.mysqlHost = hostPort;
    }
  }
}

function getEnvOrDefault(
  env: Record<string, string | undefined>,
  name: string,
  fallback: string,
): string {
  const val = env[name];
  return val !== undefined && val !== "" ? val : fallback;
}

function getFirstEnvOrDefault(
  env: Record<string, string | undefined>,
  names: string[],
  fallback: string,
): string {
  for (const name of names) {
    const val = env[name];
    if (val !== undefined && val !== "") {
      return val;
    }
  }
  return fallback;
}

function getEnvIntOrDefault(
  env: Record<string, string | undefined>,
  name: string,
  fallback: number,
): number {
  const val = env[name];
  if (val === undefined || val === "") {
    return fallback;
  }
  const parsed = Number(val);
  return Number.isFinite(parsed) && Number.isInteger(parsed) ? parsed : fallback;
}

function getFirstEnvIntOrDefault(
  env: Record<string, string | undefined>,
  names: string[],
  fallback: number,
): number {
  for (const name of names) {
    const val = env[name];
    if (val !== undefined && val !== "") {
      const parsed = Number(val);
      if (Number.isFinite(parsed) && Number.isInteger(parsed)) {
        return parsed;
      }
    }
  }
  return fallback;
}

export function loadConfig(
  env: Record<string, string | undefined> = process.env,
  dotEnvPath = ".env",
): AuthConfig {
  if (dotEnvPath) {
    loadDotEnvIfPresent(dotEnvPath, env);
  }

  const cfg = createDefaultConfig();
  cfg.host = getEnvOrDefault(env, "HOST", cfg.host);

  const parsedPort = getEnvIntOrDefault(env, "PORT", cfg.port);
  if (parsedPort > 0 && parsedPort <= 65535) {
    cfg.port = parsedPort;
  }

  const databaseUrl = getEnvOrDefault(env, "DATABASE_URL", "");
  if (databaseUrl) {
    applyDatabaseUrl(databaseUrl, cfg);
  }

  cfg.dbDriver = getFirstEnvOrDefault(env, ["DB_DRIVER", "DB_CONNECTION"], cfg.dbDriver);
  cfg.dbPath = getEnvOrDefault(env, "DB_PATH", cfg.dbPath);

  cfg.mysqlHost = getFirstEnvOrDefault(env, ["MYSQL_HOST", "DB_HOST"], cfg.mysqlHost);
  const parsedMysqlPort = getFirstEnvIntOrDefault(
    env,
    ["MYSQL_PORT", "DB_PORT"],
    cfg.mysqlPort,
  );
  if (parsedMysqlPort > 0 && parsedMysqlPort <= 65535) {
    cfg.mysqlPort = parsedMysqlPort;
  }
  cfg.mysqlUser = getFirstEnvOrDefault(
    env,
    ["MYSQL_USER", "DB_USER", "DB_USERNAME"],
    cfg.mysqlUser,
  );
  cfg.mysqlPassword = getFirstEnvOrDefault(
    env,
    ["MYSQL_PASSWORD", "DB_PASSWORD"],
    cfg.mysqlPassword,
  );
  cfg.mysqlDatabase = getFirstEnvOrDefault(
    env,
    ["MYSQL_DB", "DB_DATABASE", "DB_NAME"],
    cfg.mysqlDatabase,
  );

  cfg.jwtSecret = getEnvOrDefault(env, "JWT_SECRET", "");
  if (!cfg.jwtSecret) {
    cfg.jwtSecret = randomHex(32);
    cfg.jwtSecretIsEphemeral = true;
  }

  const accessTtl = getEnvIntOrDefault(env, "ACCESS_TOKEN_TTL_SEC", cfg.accessTokenTtlSec);
  if (accessTtl > 0) cfg.accessTokenTtlSec = accessTtl;

  const refreshTtl = getEnvIntOrDefault(env, "REFRESH_TOKEN_TTL_SEC", cfg.refreshTokenTtlSec);
  if (refreshTtl > 0) cfg.refreshTokenTtlSec = refreshTtl;

  const iterations = getEnvIntOrDefault(env, "PBKDF2_ITERATIONS", cfg.pbkdf2Iterations);
  if (iterations >= 10000) cfg.pbkdf2Iterations = iterations;

  const maxAttempts = getEnvIntOrDefault(env, "LOGIN_MAX_ATTEMPTS", cfg.maxLoginAttempts);
  if (maxAttempts > 0) cfg.maxLoginAttempts = maxAttempts;

  const rateWindow = getEnvIntOrDefault(env, "LOGIN_RATE_WINDOW_SEC", cfg.rateLimitWindowSec);
  if (rateWindow > 0) cfg.rateLimitWindowSec = rateWindow;

  return cfg;
}
