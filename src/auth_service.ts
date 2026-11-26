import type { AuthConfig } from "./config.ts";
import {
  type JwtClaims,
  constantTimeEquals,
  createJwt,
  hashPassword,
  randomHex,
  sha256Hex,
  verifyJwt,
  verifyPassword,
} from "./crypto.ts";
import type { IDatabase, UserRecord } from "./database.ts";

export interface PublicUser {
  id: number;
  username: string;
  full_name: string;
  email: string;
  phone: string;
  role: string;
  status: string;
  created_at: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface AuthResult {
  ok: boolean;
  statusCode: number;
  error: string;
  user?: PublicUser;
  tokens?: AuthTokens;
}

export class RateLimiter {
  private readonly attempts = new Map<string, number[]>();
  private readonly maxAttempts: number;
  private readonly windowSec: number;

  constructor(maxAttempts: number, windowSec: number) {
    this.maxAttempts = maxAttempts;
    this.windowSec = windowSec;
  }

  allow(key: string, nowEpochSec: number): boolean {
    if (this.maxAttempts <= 0 || this.windowSec <= 0) {
      return true;
    }
    let q = this.attempts.get(key);
    if (!q) {
      q = [];
      this.attempts.set(key, q);
    }
    const cutoff = nowEpochSec - this.windowSec;
    while (q.length > 0 && q[0]! <= cutoff) {
      q.shift();
    }
    if (q.length >= this.maxAttempts) {
      return false;
    }
    q.push(nowEpochSec);
    return true;
  }
}

const USERNAME_REGEX = /^[A-Za-z0-9_.-]+$/;
const EMAIL_REGEX = /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/;
const VALID_ROLES = new Set(["owner", "manager", "staff", "admin"]);

export class AuthService {
  private readonly db: IDatabase;
  private readonly config: AuthConfig;
  private readonly loginLimiter: RateLimiter;
  private dummyHashPromise: Promise<string> | null = null;

  constructor(db: IDatabase, config: AuthConfig) {
    this.db = db;
    this.config = config;
    this.loginLimiter = new RateLimiter(
      config.maxLoginAttempts,
      config.rateLimitWindowSec,
    );
  }

  static nowEpochSeconds(): number {
    return Math.floor(Date.now() / 1000);
  }

  private getDummyHash(): Promise<string> {
    if (!this.dummyHashPromise) {
      this.dummyHashPromise = hashPassword(
        "timing-mitigation-placeholder",
        this.config.pbkdf2Iterations,
      );
    }
    return this.dummyHashPromise;
  }

  private static normalizeLowerTrim(s: string): string {
    return s.trim().toLowerCase();
  }

  private static isValidUsername(username: string): boolean {
    return username.length >= 3 && username.length <= 50 && USERNAME_REGEX.test(username);
  }

  private static isValidEmail(email: string): boolean {
    return email.length >= 5 && email.length <= 120 && EMAIL_REGEX.test(email);
  }

  private static validatePassword(password: string): string | null {
    if (password.length < 8) {
      return "Password must be at least 8 characters long";
    }
    if (password.length > 128) {
      return "Password must be at most 128 characters long";
    }
    if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
      return "Password must include at least one letter and one number";
    }
    return null;
  }

  private static async verifyStoredPassword(
    candidate: string,
    stored: string,
  ): Promise<boolean> {
    if (stored.startsWith("pbkdf2_sha256$")) {
      return verifyPassword(candidate, stored);
    }
    // Support legacy plaintext passwords already present in smartfarm_db.users.
    return stored.length > 0 && constantTimeEquals(candidate, stored);
  }

  private static toPublicUser(user: UserRecord): PublicUser {
    return {
      id: user.id,
      username: user.username,
      full_name: user.full_name,
      email: user.email,
      phone: user.phone,
      role: user.role,
      status: user.status,
      created_at: user.created_at,
    };
  }

  private async issueTokensForUser(
    user: UserRecord,
    nowEpochSec: number,
  ): Promise<AuthTokens> {
    const claims: JwtClaims = {
      userId: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      issuedAt: nowEpochSec,
      expiresAt: nowEpochSec + this.config.accessTokenTtlSec,
      jti: randomHex(16),
    };

    const accessToken = createJwt(claims, this.config.jwtSecret);
    const refreshToken = randomHex(32);
    const refreshHash = sha256Hex(refreshToken);

    const stored = await this.db.storeRefreshToken(
      user.id,
      refreshHash,
      nowEpochSec + this.config.refreshTokenTtlSec,
      nowEpochSec,
    );
    if (!stored) {
      throw new Error("Failed to store refresh token");
    }

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: "Bearer",
      expires_in: this.config.accessTokenTtlSec,
    };
  }

  async registerUser(
    username: string,
    password: string,
    fullName: string,
    email = "",
    phone = "",
    role = "owner",
  ): Promise<AuthResult> {
    const cleanUsername = username.trim();
    const cleanFullName = fullName.trim();
    const cleanEmail = AuthService.normalizeLowerTrim(email);
    const cleanPhone = phone.trim();
    const cleanRole = role ? AuthService.normalizeLowerTrim(role) : "owner";

    if (!AuthService.isValidUsername(cleanUsername)) {
      return {
        ok: false,
        statusCode: 400,
        error: "Username must be 3-50 characters (letters, digits, _, ., -)",
      };
    }
    if (!cleanFullName || cleanFullName.length > 100) {
      return {
        ok: false,
        statusCode: 400,
        error: "full_name is required (max 100 characters)",
      };
    }
    if (cleanEmail && !AuthService.isValidEmail(cleanEmail)) {
      return { ok: false, statusCode: 400, error: "Invalid email address" };
    }
    if (cleanPhone.length > 30) {
      return {
        ok: false,
        statusCode: 400,
        error: "phone must be at most 30 characters",
      };
    }
    if (!VALID_ROLES.has(cleanRole)) {
      return {
        ok: false,
        statusCode: 400,
        error: "role must be one of: owner, manager, staff, admin",
      };
    }
    const pwErr = AuthService.validatePassword(password);
    if (pwErr) {
      return { ok: false, statusCode: 400, error: pwErr };
    }

    if (cleanEmail && (await this.db.findUserByEmail(cleanEmail))) {
      return { ok: false, statusCode: 409, error: "Email already exists" };
    }

    const now = AuthService.nowEpochSeconds();
    const passwordHash = await hashPassword(password, this.config.pbkdf2Iterations);

    const created = await this.db.createUser(
      cleanUsername,
      passwordHash,
      cleanFullName,
      cleanEmail,
      cleanPhone,
      cleanRole,
    );
    if (!created.user) {
      return {
        ok: false,
        statusCode: 409,
        error: created.error ?? "Failed to create user",
      };
    }

    const tokens = await this.issueTokensForUser(created.user, now);
    return {
      ok: true,
      statusCode: 201,
      error: "",
      user: AuthService.toPublicUser(created.user),
      tokens,
    };
  }

  async login(
    identifier: string,
    password: string,
    clientIp: string,
  ): Promise<AuthResult> {
    const now = AuthService.nowEpochSeconds();
    const rateKey = clientIp || "unknown";
    if (!this.loginLimiter.allow(rateKey, now)) {
      return {
        ok: false,
        statusCode: 429,
        error: "Too many login attempts. Please try again later.",
      };
    }

    const cleanId = identifier.trim();
    if (!cleanId || !password) {
      return {
        ok: false,
        statusCode: 400,
        error: "Identifier and password are required",
      };
    }

    const user = cleanId.includes("@")
      ? await this.db.findUserByEmail(AuthService.normalizeLowerTrim(cleanId))
      : await this.db.findUserByUsername(cleanId);

    if (!user) {
      await verifyPassword(password, await this.getDummyHash());
      return { ok: false, statusCode: 401, error: "Invalid credentials" };
    }

    if (!(await AuthService.verifyStoredPassword(password, user.password))) {
      return { ok: false, statusCode: 401, error: "Invalid credentials" };
    }

    if (user.status !== "active") {
      return { ok: false, statusCode: 403, error: "User account is inactive" };
    }

    const tokens = await this.issueTokensForUser(user, now);
    return {
      ok: true,
      statusCode: 200,
      error: "",
      user: AuthService.toPublicUser(user),
      tokens,
    };
  }

  async refreshSession(refreshToken: string): Promise<AuthResult> {
    const cleanToken = refreshToken.trim();
    if (!cleanToken) {
      return { ok: false, statusCode: 400, error: "refresh_token is required" };
    }

    const now = AuthService.nowEpochSeconds();
    const tokenHash = sha256Hex(cleanToken);
    const record = await this.db.findRefreshToken(tokenHash);
    if (!record || record.revoked || record.expires_at <= now) {
      return {
        ok: false,
        statusCode: 401,
        error: "Invalid or expired refresh token",
      };
    }

    if (!(await this.db.revokeRefreshToken(tokenHash))) {
      return {
        ok: false,
        statusCode: 401,
        error: "Invalid or expired refresh token",
      };
    }

    const user = await this.db.findUserById(record.user_id);
    if (!user) {
      return { ok: false, statusCode: 401, error: "User no longer exists" };
    }
    if (user.status !== "active") {
      return { ok: false, statusCode: 403, error: "User account is inactive" };
    }

    const tokens = await this.issueTokensForUser(user, now);
    return {
      ok: true,
      statusCode: 200,
      error: "",
      user: AuthService.toPublicUser(user),
      tokens,
    };
  }

  async logout(refreshToken: string): Promise<AuthResult> {
    const cleanToken = refreshToken.trim();
    if (!cleanToken) {
      return { ok: false, statusCode: 400, error: "refresh_token is required" };
    }
    const tokenHash = sha256Hex(cleanToken);
    await this.db.revokeRefreshToken(tokenHash);
    return { ok: true, statusCode: 200, error: "" };
  }

  async logoutAll(userId: number): Promise<AuthResult> {
    await this.db.revokeAllUserRefreshTokens(userId);
    return { ok: true, statusCode: 200, error: "" };
  }

  authenticateAccessToken(bearerToken: string): JwtClaims | null {
    if (!bearerToken) {
      return null;
    }
    return verifyJwt(
      bearerToken,
      this.config.jwtSecret,
      AuthService.nowEpochSeconds(),
    );
  }

  async getProfile(userId: number): Promise<AuthResult> {
    const user = await this.db.findUserById(userId);
    if (!user) {
      return { ok: false, statusCode: 404, error: "User not found" };
    }
    return {
      ok: true,
      statusCode: 200,
      error: "",
      user: AuthService.toPublicUser(user),
    };
  }

  async changePassword(
    userId: number,
    currentPassword: string,
    newPassword: string,
  ): Promise<AuthResult> {
    if (!currentPassword || !newPassword) {
      return {
        ok: false,
        statusCode: 400,
        error: "current_password and new_password are required",
      };
    }
    const pwErr = AuthService.validatePassword(newPassword);
    if (pwErr) {
      return { ok: false, statusCode: 400, error: pwErr };
    }

    const user = await this.db.findUserById(userId);
    if (!user) {
      return { ok: false, statusCode: 404, error: "User not found" };
    }

    if (!(await AuthService.verifyStoredPassword(currentPassword, user.password))) {
      return {
        ok: false,
        statusCode: 401,
        error: "Current password is incorrect",
      };
    }

    const newHash = await hashPassword(newPassword, this.config.pbkdf2Iterations);
    if (!(await this.db.updatePassword(userId, newHash))) {
      return { ok: false, statusCode: 500, error: "Failed to update password" };
    }

    await this.db.revokeAllUserRefreshTokens(userId);
    return { ok: true, statusCode: 200, error: "" };
  }
}
