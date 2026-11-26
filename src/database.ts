import { Database } from "bun:sqlite";

export interface UserRecord {
  id: number;
  username: string;
  password: string;
  full_name: string;
  email: string;
  phone: string;
  role: string;
  status: string;
  created_at: string;
}

export interface RefreshTokenRecord {
  id: number;
  user_id: number;
  token_hash: string;
  expires_at: number;
  revoked: boolean;
  created_at: number;
}

export interface CreateUserResult {
  user?: UserRecord;
  error?: string;
}

export interface IDatabase {
  initSchema(): Promise<void>;
  createUser(
    username: string,
    passwordHash: string,
    fullName: string,
    email: string,
    phone: string,
    role: string,
  ): Promise<CreateUserResult>;
  findUserByEmail(email: string): Promise<UserRecord | null>;
  findUserByUsername(username: string): Promise<UserRecord | null>;
  findUserById(userId: number): Promise<UserRecord | null>;
  updatePassword(userId: number, newPasswordHash: string): Promise<boolean>;
  storeRefreshToken(
    userId: number,
    tokenHash: string,
    expiresAt: number,
    nowEpochSec: number,
  ): Promise<boolean>;
  findRefreshToken(tokenHash: string): Promise<RefreshTokenRecord | null>;
  revokeRefreshToken(tokenHash: string): Promise<boolean>;
  revokeAllUserRefreshTokens(userId: number): Promise<boolean>;
  close(): Promise<void>;
}

interface RawUserRow {
  id: number;
  username: string;
  password: string;
  full_name: string;
  email: string | null;
  phone: string | null;
  role: string;
  status: string;
  created_at: string;
}

interface RawRefreshTokenRow {
  id: number;
  user_id: number;
  token_hash: string;
  expires_at: number;
  revoked: number;
  created_at: number;
}

function currentTimestampUtc(): string {
  return new Date().toISOString().slice(0, 19).replace("T", " ");
}

function mapUserRow(row: RawUserRow): UserRecord {
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

export class SqliteDatabase implements IDatabase {
  private readonly db: Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath, { create: true });
    this.db.exec("PRAGMA busy_timeout = 5000;");
    this.db.exec("PRAGMA foreign_keys = ON;");
    if (dbPath !== ":memory:") {
      this.db.exec("PRAGMA journal_mode = WAL;");
    }
  }

  async initSchema(): Promise<void> {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password TEXT NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT COLLATE NOCASE,
        phone TEXT,
        role TEXT NOT NULL DEFAULT 'owner',
        status TEXT NOT NULL DEFAULT 'active',
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at INTEGER NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
    `);
  }

  async createUser(
    username: string,
    passwordHash: string,
    fullName: string,
    email: string,
    phone: string,
    role: string,
  ): Promise<CreateUserResult> {
    const createdAt = currentTimestampUtc();
    const stmt = this.db.query(`
      INSERT INTO users (username, password, full_name, email, phone, role, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 'active', ?);
    `);

    try {
      const info = stmt.run(
        username,
        passwordHash,
        fullName,
        email || null,
        phone || null,
        role,
        createdAt,
      );
      return {
        user: {
          id: Number(info.lastInsertRowid),
          username,
          password: passwordHash,
          full_name: fullName,
          email,
          phone,
          role,
          status: "active",
          created_at: createdAt,
        },
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("SQLITE_CONSTRAINT") || msg.includes("UNIQUE constraint failed")) {
        return { error: "Username already exists" };
      }
      return { error: msg };
    }
  }

  async findUserByEmail(email: string): Promise<UserRecord | null> {
    const row = this.db
      .query<RawUserRow, [string]>(
        "SELECT id, username, password, full_name, email, phone, role, status, created_at FROM users WHERE email = ? LIMIT 1;",
      )
      .get(email);
    return row ? mapUserRow(row) : null;
  }

  async findUserByUsername(username: string): Promise<UserRecord | null> {
    const row = this.db
      .query<RawUserRow, [string]>(
        "SELECT id, username, password, full_name, email, phone, role, status, created_at FROM users WHERE username = ? LIMIT 1;",
      )
      .get(username);
    return row ? mapUserRow(row) : null;
  }

  async findUserById(userId: number): Promise<UserRecord | null> {
    const row = this.db
      .query<RawUserRow, [number]>(
        "SELECT id, username, password, full_name, email, phone, role, status, created_at FROM users WHERE id = ?;",
      )
      .get(userId);
    return row ? mapUserRow(row) : null;
  }

  async updatePassword(userId: number, newPasswordHash: string): Promise<boolean> {
    const info = this.db
      .query("UPDATE users SET password = ? WHERE id = ?;")
      .run(newPasswordHash, userId);
    return info.changes > 0;
  }

  async storeRefreshToken(
    userId: number,
    tokenHash: string,
    expiresAt: number,
    nowEpochSec: number,
  ): Promise<boolean> {
    const info = this.db
      .query(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked, created_at) VALUES (?, ?, ?, 0, ?);",
      )
      .run(userId, tokenHash, expiresAt, nowEpochSec);
    return info.changes > 0;
  }

  async findRefreshToken(tokenHash: string): Promise<RefreshTokenRecord | null> {
    const row = this.db
      .query<RawRefreshTokenRow, [string]>(
        "SELECT id, user_id, token_hash, expires_at, revoked, created_at FROM refresh_tokens WHERE token_hash = ?;",
      )
      .get(tokenHash);
    if (!row) {
      return null;
    }
    return {
      id: Number(row.id),
      user_id: Number(row.user_id),
      token_hash: row.token_hash,
      expires_at: Number(row.expires_at),
      revoked: row.revoked !== 0,
      created_at: Number(row.created_at),
    };
  }

  async revokeRefreshToken(tokenHash: string): Promise<boolean> {
    const info = this.db
      .query("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ? AND revoked = 0;")
      .run(tokenHash);
    return info.changes > 0;
  }

  async revokeAllUserRefreshTokens(userId: number): Promise<boolean> {
    this.db
      .query("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0;")
      .run(userId);
    return true;
  }

  async close(): Promise<void> {
    this.db.close();
  }
}
