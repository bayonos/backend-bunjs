import {
  createHash,
  createHmac,
  pbkdf2 as pbkdf2Callback,
  randomBytes as nodeRandomBytes,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";

const pbkdf2Async = promisify(pbkdf2Callback);

export interface JwtClaims {
  userId: number;
  username: string;
  email: string;
  role: string;
  issuedAt: number;
  expiresAt: number;
  jti: string;
}

export function toHex(data: Uint8Array): string {
  return Buffer.from(data).toString("hex");
}

export function fromHex(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    return null;
  }
  return new Uint8Array(Buffer.from(hex, "hex"));
}

export function base64UrlEncode(data: Uint8Array | string): string {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
  return buf.toString("base64url");
}

export function base64UrlDecode(encoded: string): string | null {
  if (encoded === "") {
    return "";
  }
  if (!/^[A-Za-z0-9\-_]+={0,2}$/.test(encoded)) {
    return null;
  }
  try {
    return Buffer.from(encoded, "base64url").toString("utf8");
  } catch {
    return null;
  }
}

export function randomBytes(numBytes: number): Uint8Array {
  return new Uint8Array(nodeRandomBytes(numBytes));
}

export function randomHex(numBytes: number): string {
  return toHex(randomBytes(numBytes));
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

export function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    return false;
  }
  if (bufA.length === 0) {
    return true;
  }
  return timingSafeEqual(bufA, bufB);
}

// Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
export async function hashPassword(password: string, iterations = 210000): Promise<string> {
  const salt = randomBytes(16);
  const derived = await pbkdf2Async(password, salt, iterations, 32, "sha256");
  return `pbkdf2_sha256$${iterations}$${toHex(salt)}$${toHex(new Uint8Array(derived))}`;
}

export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const parts = storedHash.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256") {
    return false;
  }
  const iterations = Number.parseInt(parts[1] ?? "", 10);
  if (!Number.isInteger(iterations) || iterations <= 0 || String(iterations) !== parts[1]) {
    return false;
  }

  const salt = fromHex(parts[2] ?? "");
  const expected = fromHex(parts[3] ?? "");
  if (!salt || !expected || expected.length === 0) {
    return false;
  }

  const derived = await pbkdf2Async(password, salt, iterations, expected.length, "sha256");
  return timingSafeEqual(derived, expected);
}

export function createJwt(claims: JwtClaims, secret: string): string {
  const header = { alg: "HS256", typ: "JWT" };
  const payload = {
    sub: claims.userId,
    username: claims.username,
    email: claims.email,
    role: claims.role,
    iat: claims.issuedAt,
    exp: claims.expiresAt,
    jti: claims.jti,
  };

  const signingInput = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(payload))}`;
  const sig = createHmac("sha256", secret).update(signingInput, "utf8").digest();
  return `${signingInput}.${base64UrlEncode(sig)}`;
}

export function verifyJwt(
  token: string,
  secret: string,
  nowEpochSec: number,
): JwtClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }
  const [headerPart, payloadPart, sigPart] = parts;
  if (!headerPart || !payloadPart || !sigPart) {
    return null;
  }

  const signingInput = `${headerPart}.${payloadPart}`;
  const expectedSig = createHmac("sha256", secret).update(signingInput, "utf8").digest();
  const expectedSigB64 = base64UrlEncode(expectedSig);

  if (!constantTimeEquals(sigPart, expectedSigB64)) {
    return null;
  }

  const headerStr = base64UrlDecode(headerPart);
  const payloadStr = base64UrlDecode(payloadPart);
  if (headerStr === null || payloadStr === null) {
    return null;
  }

  let headerJson: Record<string, unknown>;
  let payloadJson: Record<string, unknown>;
  try {
    headerJson = JSON.parse(headerStr) as Record<string, unknown>;
    payloadJson = JSON.parse(payloadStr) as Record<string, unknown>;
  } catch {
    return null;
  }

  if (!headerJson || typeof headerJson !== "object" || headerJson.alg !== "HS256") {
    return null;
  }

  if (
    typeof payloadJson.sub !== "number" ||
    !Number.isInteger(payloadJson.sub) ||
    typeof payloadJson.exp !== "number" ||
    typeof payloadJson.username !== "string" ||
    typeof payloadJson.email !== "string"
  ) {
    return null;
  }

  const claims: JwtClaims = {
    userId: payloadJson.sub,
    username: payloadJson.username,
    email: payloadJson.email,
    role: typeof payloadJson.role === "string" ? payloadJson.role : "",
    issuedAt: typeof payloadJson.iat === "number" ? payloadJson.iat : 0,
    expiresAt: payloadJson.exp,
    jti: typeof payloadJson.jti === "string" ? payloadJson.jti : "",
  };

  if (claims.userId <= 0 || claims.expiresAt <= nowEpochSec) {
    return null;
  }

  return claims;
}
