import type { AuthResult, AuthService } from "./auth_service.ts";

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function jsonResponse(statusCode: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: statusCode,
    headers: {
      ...CORS_HEADERS,
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function errorResponse(statusCode: number, message: string): Response {
  return jsonResponse(statusCode, { error: message });
}

function authResultToResponse(result: AuthResult): Response {
  if (!result.ok) {
    return errorResponse(result.statusCode, result.error);
  }
  const body: Record<string, unknown> = {};
  if (result.user) {
    body.user = result.user;
  }
  if (result.tokens) {
    body.access_token = result.tokens.access_token;
    body.refresh_token = result.tokens.refresh_token;
    body.token_type = result.tokens.token_type;
    body.expires_in = result.tokens.expires_in;
  }
  return jsonResponse(result.statusCode, body);
}

function extractBearerToken(req: Request): string | null {
  const header = req.headers.get("Authorization");
  if (!header || !header.startsWith("Bearer ")) {
    return null;
  }
  const token = header.slice("Bearer ".length);
  return token || null;
}

async function parseJsonObject(
  req: Request,
): Promise<Record<string, unknown> | null> {
  try {
    const parsed: unknown = await req.json();
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return null;
    }
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

function getStringField(
  obj: Record<string, unknown>,
  key: string,
): string | null {
  const val = obj[key];
  return typeof val === "string" ? val : null;
}

export interface RequestServerContext {
  requestIP?(req: Request): { address: string } | null;
}

function extractClientIp(
  req: Request,
  server?: RequestServerContext,
): string {
  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) {
      return first;
    }
  }
  const realIp = req.headers.get("x-real-ip")?.trim();
  if (realIp) {
    return realIp;
  }
  const socketIp = server?.requestIP?.(req)?.address;
  return socketIp ?? "127.0.0.1";
}

export function createFetchHandler(authService: AuthService) {
  return async (
    req: Request,
    server?: RequestServerContext,
  ): Promise<Response> => {
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const pathname = new URL(req.url).pathname;

    if (req.method === "GET" && pathname === "/") {
      return jsonResponse(200, {
        status: "ok",
        service: "smartfarm-auth-backend",
        endpoints: [
          "GET /health",
          "POST /api/auth/register",
          "POST /api/auth/login",
          "POST /api/auth/refresh",
          "POST /api/auth/logout",
          "POST /api/auth/logout-all",
          "GET /api/auth/me",
          "POST /api/auth/change-password",
        ],
      });
    }

    if (req.method === "GET" && (pathname === "/health" || pathname === "/healthz")) {
      return jsonResponse(200, { status: "ok" });
    }

    if (
      req.method === "POST" &&
      (pathname === "/api/auth/register" || pathname === "/auth/register")
    ) {
      const body = await parseJsonObject(req);
      if (!body) {
        return errorResponse(400, "Invalid JSON request body");
      }
      const username = getStringField(body, "username");
      const password = getStringField(body, "password");
      if (username === null || password === null) {
        return errorResponse(400, "username and password are required strings");
      }
      const fullName = getStringField(body, "full_name") ?? username;
      const email = getStringField(body, "email") ?? "";
      const phone = getStringField(body, "phone") ?? "";
      const role = getStringField(body, "role") ?? "owner";

      return authResultToResponse(
        await authService.registerUser(username, password, fullName, email, phone, role),
      );
    }

    if (
      req.method === "POST" &&
      (pathname === "/api/auth/login" || pathname === "/auth/login")
    ) {
      const body = await parseJsonObject(req);
      if (!body) {
        return errorResponse(400, "Invalid JSON request body");
      }
      const identifier =
        getStringField(body, "identifier") ??
        getStringField(body, "email") ??
        getStringField(body, "username");
      const password = getStringField(body, "password");
      if (identifier === null || password === null) {
        return errorResponse(
          400,
          "username (or email/identifier) and password are required",
        );
      }
      const clientIp = extractClientIp(req, server);
      return authResultToResponse(
        await authService.login(identifier, password, clientIp),
      );
    }

    if (
      req.method === "POST" &&
      (pathname === "/api/auth/refresh" || pathname === "/auth/refresh")
    ) {
      const body = await parseJsonObject(req);
      if (!body) {
        return errorResponse(400, "Invalid JSON request body");
      }
      const refreshToken = getStringField(body, "refresh_token");
      if (refreshToken === null) {
        return errorResponse(400, "refresh_token is required");
      }
      return authResultToResponse(await authService.refreshSession(refreshToken));
    }

    if (
      req.method === "POST" &&
      (pathname === "/api/auth/logout" || pathname === "/auth/logout")
    ) {
      const body = await parseJsonObject(req);
      if (!body) {
        return errorResponse(400, "Invalid JSON request body");
      }
      const refreshToken = getStringField(body, "refresh_token");
      if (refreshToken === null) {
        return errorResponse(400, "refresh_token is required");
      }
      const res = await authService.logout(refreshToken);
      if (!res.ok) {
        return errorResponse(res.statusCode, res.error);
      }
      return jsonResponse(200, { message: "Logged out" });
    }

    if (
      req.method === "POST" &&
      (pathname === "/api/auth/logout-all" || pathname === "/auth/logout-all")
    ) {
      const token = extractBearerToken(req);
      if (!token) {
        return errorResponse(401, "Missing or invalid Authorization header");
      }
      const claims = authService.authenticateAccessToken(token);
      if (!claims) {
        return errorResponse(401, "Invalid or expired access token");
      }
      await authService.logoutAll(claims.userId);
      return jsonResponse(200, { message: "All sessions revoked" });
    }

    if (
      req.method === "GET" &&
      (pathname === "/api/auth/me" || pathname === "/auth/me")
    ) {
      const token = extractBearerToken(req);
      if (!token) {
        return errorResponse(401, "Missing or invalid Authorization header");
      }
      const claims = authService.authenticateAccessToken(token);
      if (!claims) {
        return errorResponse(401, "Invalid or expired access token");
      }
      return authResultToResponse(await authService.getProfile(claims.userId));
    }

    if (
      req.method === "POST" &&
      (pathname === "/api/auth/change-password" || pathname === "/auth/change-password")
    ) {
      const token = extractBearerToken(req);
      if (!token) {
        return errorResponse(401, "Missing or invalid Authorization header");
      }
      const claims = authService.authenticateAccessToken(token);
      if (!claims) {
        return errorResponse(401, "Invalid or expired access token");
      }
      const body = await parseJsonObject(req);
      if (!body) {
        return errorResponse(400, "Invalid JSON request body");
      }
      const currentPassword = getStringField(body, "current_password");
      const newPassword = getStringField(body, "new_password");
      if (currentPassword === null || newPassword === null) {
        return errorResponse(400, "current_password and new_password are required");
      }
      const res = await authService.changePassword(
        claims.userId,
        currentPassword,
        newPassword,
      );
      if (!res.ok) {
        return errorResponse(res.statusCode, res.error);
      }
      return jsonResponse(200, {
        message: "Password updated; all refresh tokens revoked",
      });
    }

    return errorResponse(404, "Not found");
  };
}

export function startServer(
  authService: AuthService,
  host: string,
  port: number,
) {
  const fetchHandler = createFetchHandler(authService);
  return Bun.serve({
    hostname: host,
    port,
    fetch: (req, server) => fetchHandler(req, server),
  });
}
