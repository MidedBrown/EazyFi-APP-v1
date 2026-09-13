const crypto = require("node:crypto");

const { createSupabase } = require("./supabase");
const {
  timingSafeEqualStrings,
  randomHex
} = require("./security");

const ADMIN_SESSION_COOKIE = "eazyfi_admin_session";
const ADMIN_SESSION_TTL_SECONDS = 30 * 60;

function getAdminApiKey() {
  const key = process.env.ADMIN_API_KEY;

  if (!key) {
    throw new Error("ADMIN_API_KEY is not configured.");
  }

  return key;
}

function hashSessionToken(token) {
  return crypto
    .createHash("sha256")
    .update(token, "utf8")
    .digest("hex");
}

async function createAdminSession() {
  const supabase = createSupabase();

  const token = randomHex(48);
  const tokenHash = hashSessionToken(token);

  const expiresAt = new Date(
    Date.now() + ADMIN_SESSION_TTL_SECONDS * 1000
  ).toISOString();

  const { error } = await supabase
    .from("admin_sessions")
    .insert({
      session_token_hash: tokenHash,
      expires_at: expiresAt
    });

  if (error) {
    throw error;
  }

  return {
    token,
    expiresAt
  };
}

async function getAdminSession(token) {
  if (!token) {
    return null;
  }

  const supabase = createSupabase();
  const tokenHash = hashSessionToken(token);

  const { data, error } = await supabase
    .from("admin_sessions")
    .select("id, created_at, expires_at, revoked_at")
    .eq("session_token_hash", tokenHash)
    .is("revoked_at", null)
    .gt("expires_at", new Date().toISOString())
    .maybeSingle();

  if (error) {
    throw error;
  }

  return data || null;
}

async function destroyAdminSession(token) {
  if (!token) {
    return;
  }

  const supabase = createSupabase();
  const tokenHash = hashSessionToken(token);

  const { error } = await supabase
    .from("admin_sessions")
    .update({
      revoked_at: new Date().toISOString()
    })
    .eq("session_token_hash", tokenHash)
    .is("revoked_at", null);

  if (error) {
    throw error;
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
      try {
        cookies[name] = decodeURIComponent(value);
      } catch {
        cookies[name] = value;
      }
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

  return timingSafeEqualStrings(
    suppliedKey,
    getAdminApiKey()
  );
}

async function requireAdminAuthentication(req, res) {
  const sessionToken = getAdminSessionToken(req);

  try {
    const session = await getAdminSession(sessionToken);

    if (session) {
      return {
        authenticated: true,
        method: "session",
        sessionToken,
        session
      };
    }

    /*
     * Keep API-key authentication available for
     * trusted server-to-server admin requests.
     *
     * The browser dashboard will use the HttpOnly
     * session cookie instead of exposing ADMIN_API_KEY.
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
  } catch (error) {
    console.error(
      "[EazyFi] Admin authentication failed:",
      error?.message || error
    );

    res.status(500).json({
      success: false,
      error: "Unable to verify admin authentication."
    });

    return null;
  }
}

function setAdminSessionCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    `${ADMIN_SESSION_COOKIE}=${encodeURIComponent(
      token
    )}; Max-Age=${ADMIN_SESSION_TTL_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Strict`
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
    Math.floor(
      (new Date(session.expires_at).getTime() - Date.now()) / 1000
    )
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
