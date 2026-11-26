import { SQL } from "bun";
import type {
  CreateUserResult,
  IDatabase,
  RefreshTokenRecord,
  UserRecord,
} from "./database.ts";

interface MysqlUserRow {
  id: number | bigint;
  username: string;
  password: string;
  full_name: string;
  email: string | null;
  phone: string | null;
  role: string;
  status: string;
  created_at: string | null;
}

interface MysqlRefreshTokenRow {
  id: number | bigint;
  user_id: number | bigint;
  token_hash: string;
  expires_at: number | bigint;
  revoked: number;
  created_at: number | bigint;
}

function mapUserRow(row: MysqlUserRow): UserRecord {
  return {
    id: Number(row.id),
    username: row.username ?? "",
    password: row.password ?? "",
    full_name: row.full_name ?? "",
    email: row.email ?? "",
    phone: row.phone ?? "",
    role: row.role ?? "",
    status: row.status ?? "",
    created_at: row.created_at ?? "",
  };
}

function isDuplicateEntryError(err: unknown): boolean {
  if (!err || typeof err !== "object") {
    return false;
  }
  const e = err as { errno?: number; code?: string; message?: string };
  return (
    e.errno === 1062 ||
    e.code === "ER_DUP_ENTRY" ||
    (typeof e.message === "string" && e.message.includes("Duplicate entry"))
  );
}

export class MysqlDatabase implements IDatabase {
  private readonly sql: SQL;

  constructor(
    host: string,
    port: number,
    user: string,
    password: string,
    database: string,
  ) {
    this.sql = new SQL({
      adapter: "mysql",
      hostname: host,
      port,
      username: user,
      password,
      database,
    });
  }

  async initSchema(): Promise<void> {
    await this.sql`
      CREATE TABLE IF NOT EXISTS users (
        id INT NOT NULL AUTO_INCREMENT,
        username VARCHAR(50) NOT NULL,
        password VARCHAR(255) NOT NULL,
        full_name VARCHAR(100) NOT NULL,
        email VARCHAR(120) DEFAULT NULL,
        phone VARCHAR(30) DEFAULT NULL,
        role ENUM('owner','manager','staff','admin') NOT NULL DEFAULT 'owner',
        status ENUM('active','inactive') NOT NULL DEFAULT 'active',
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY username (username)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `;

    await this.sql`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id BIGINT NOT NULL AUTO_INCREMENT,
        user_id INT NOT NULL,
        token_hash CHAR(64) NOT NULL,
        expires_at BIGINT NOT NULL,
        revoked TINYINT(1) NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY uk_refresh_tokens_hash (token_hash),
        KEY idx_refresh_tokens_user_id (user_id),
        CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id)
          REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `;
  }

  async createUser(
    username: string,
    passwordHash: string,
    fullName: string,
    email: string,
    phone: string,
    role: string,
  ): Promise<CreateUserResult> {
    try {
      const res = await this.sql`
        INSERT INTO users (username, password, full_name, email, phone, role, status)
        VALUES (${username}, ${passwordHash}, ${fullName}, ${email || null}, ${phone || null}, ${role}, 'active')
      `;
      const newId = Number((res as unknown as { lastInsertRowid?: number | bigint }).lastInsertRowid ?? 0);
      if (newId > 0) {
        const user = await this.findUserById(newId);
        if (user) {
          return { user };
        }
      }
      const fallback = await this.findUserByUsername(username);
      if (fallback) {
        return { user: fallback };
      }
      return { error: "Failed to load newly created user" };
    } catch (err) {
      if (isDuplicateEntryError(err)) {
        return { error: "Username already exists" };
      }
      return { error: err instanceof Error ? err.message : String(err) };
    }
  }

  async findUserByEmail(email: string): Promise<UserRecord | null> {
    const rows = (await this.sql`
      SELECT id, username, password, full_name, email, phone, role, status,
             COALESCE(DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s'), '') AS created_at
      FROM users
      WHERE LOWER(email) = LOWER(${email})
      LIMIT 1
    `) as MysqlUserRow[];
    return rows[0] ? mapUserRow(rows[0]) : null;
  }

  async findUserByUsername(username: string): Promise<UserRecord | null> {
    const rows = (await this.sql`
      SELECT id, username, password, full_name, email, phone, role, status,
             COALESCE(DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s'), '') AS created_at
      FROM users
      WHERE LOWER(username) = LOWER(${username})
      LIMIT 1
    `) as MysqlUserRow[];
    return rows[0] ? mapUserRow(rows[0]) : null;
  }

  async findUserById(userId: number): Promise<UserRecord | null> {
    const rows = (await this.sql`
      SELECT id, username, password, full_name, email, phone, role, status,
             COALESCE(DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s'), '') AS created_at
      FROM users
      WHERE id = ${userId}
      LIMIT 1
    `) as MysqlUserRow[];
    return rows[0] ? mapUserRow(rows[0]) : null;
  }

  async updatePassword(userId: number, newPasswordHash: string): Promise<boolean> {
    try {
      const res = await this.sql`
        UPDATE users SET password = ${newPasswordHash} WHERE id = ${userId}
      `;
      const affected = Number((res as unknown as { affectedRows?: number }).affectedRows ?? 0);
      return affected > 0;
    } catch {
      return false;
    }
  }

  async storeRefreshToken(
    userId: number,
    tokenHash: string,
    expiresAt: number,
    nowEpochSec: number,
  ): Promise<boolean> {
    try {
      await this.sql`
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked, created_at)
        VALUES (${userId}, ${tokenHash}, ${expiresAt}, 0, ${nowEpochSec})
      `;
      return true;
    } catch {
      return false;
    }
  }

  async findRefreshToken(tokenHash: string): Promise<RefreshTokenRecord | null> {
    const rows = (await this.sql`
      SELECT id, user_id, token_hash, expires_at, revoked, created_at
      FROM refresh_tokens
      WHERE token_hash = ${tokenHash}
      LIMIT 1
    `) as MysqlRefreshTokenRow[];
    const row = rows[0];
    if (!row) {
      return null;
    }
    return {
      id: Number(row.id),
      user_id: Number(row.user_id),
      token_hash: row.token_hash,
      expires_at: Number(row.expires_at),
      revoked: Number(row.revoked) !== 0,
      created_at: Number(row.created_at),
    };
  }

  async revokeRefreshToken(tokenHash: string): Promise<boolean> {
    try {
      const res = await this.sql`
        UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ${tokenHash} AND revoked = 0
      `;
      const affected = Number((res as unknown as { affectedRows?: number }).affectedRows ?? 0);
      return affected > 0;
    } catch {
      return false;
    }
  }

  async revokeAllUserRefreshTokens(userId: number): Promise<boolean> {
    try {
      await this.sql`
        UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ${userId} AND revoked = 0
      `;
      return true;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    await this.sql.close();
  }
}
