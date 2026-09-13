const crypto = require("node:crypto");

const {
  timingSafeEqualStrings,
  randomHex
} = require("./security");

const ADMIN_SESSION_COOKIE = "eazyfi_admin_session";
const ADMIN_SESSION_TTL_SECONDS = 30 * 60;

const sessions = new Map();

function cleanupSessions() {
  const now = Date.now();

  for (const [token, session] of sessions.entries()) {
    if (session.expiresAt <= now) {
      sessions.delete(token);
    }
  }
}

setInterval(cleanupSessions, 5 * 60 * 1000).unref();

function getAdminApiKey() {
  const key = process.env.ADMIN_API_KEY;

  if (!key) {
    throw new Error("ADMIN_API_KEY is not configured.");
  }

  return key;
}

function createAdminSession() {
  const token = randomHex(48);

  sessions.set(token, {
    createdAt: Date.now(),
    expiresAt: Date.now() + ADMIN_SESSION_TTL_SECONDS * 1000
  });

  return token;
}

function getAdminSession(token) {
  if (!token) {
    return null;
  }

  const session = sessions.get(token);

  if (!session) {
    return null;
  }

  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }

  return session;
}

function destroyAdminSession(token) {
  if (token) {
    sessions.delete(token);
  }
}

function parseCookies(req) {
  const header = req.headers?.cookie || "";
  const cookies = {};

  for (const part of header.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) {
      continue;
    }

    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (name) {
      cookies[name] = decodeURIComponent(value);
    }
  }

  return cookies;
}

function getAdminSessionToken(req) {
  const cookies = parseCookies(req);
  return cookies[ADMIN_SESSION_COOKIE] || "";
}

function authenticateAdminApiKey(req) {
  const suppliedKey = req.headers["x-admin-api-key"];

  if (typeof suppliedKey !== "string" || !suppliedKey) {
    return false;
  }

  return timingSafeEqualStrings(suppliedKey, getAdminApiKey());
}

function requireAdminAuthentication(req, res) {
  const sessionToken = getAdminSessionToken(req);
  const session = getAdminSession(sessionToken);

  if (session) {
    return {
      authenticated: true,
      method: "session",
      sessionToken,
      session
    };
  }

  /*
   * Keep the existing server-to-server API-key
   * authentication available for backend/admin tools.
   *
   * The browser dashboard will use the HttpOnly
   * admin session instead of exposing ADMIN_API_KEY.
   */
  if (authenticateAdminApiKey(req)) {
    return {
      authenticated: true,
      method: "api_key",
      sessionToken: null,
      session: null
    };
  }

  res.status(401).json({
    success: false,
    error: "Admin authentication required."
  });

  return null;
}

function setAdminSessionCookie(res, token) {
  const maxAge = ADMIN_SESSION_TTL_SECONDS;

  res.setHeader(
    "Set-Cookie",
    `${ADMIN_SESSION_COOKIE}=${encodeURIComponent(token)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Strict`
  );
}

function clearAdminSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${ADMIN_SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict`
  );
}

function getAdminSessionRemainingSeconds(session) {
  if (!session) {
    return 0;
  }

  return Math.max(
    0,
    Math.floor((session.expiresAt - Date.now()) / 1000)
  );
}

module.exports = {
  ADMIN_SESSION_COOKIE,
  ADMIN_SESSION_TTL_SECONDS,
  getAdminApiKey,
  createAdminSession,
  getAdminSession,
  destroyAdminSession,
  getAdminSessionToken,
  requireAdminAuthentication,
  setAdminSessionCookie,
  clearAdminSessionCookie,
  getAdminSessionRemainingSeconds
};
