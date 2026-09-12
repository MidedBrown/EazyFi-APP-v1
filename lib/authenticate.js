const crypto = require("crypto");
const {
  createAuthSupabase,
  createSupabase
} = require("./supabase");

const SESSION_DURATION_MS = 30 * 60 * 1000; // 30 minutes


function parseCookies(req) {
  const header = req.headers.cookie || "";
  const cookies = {};

  for (const part of header.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) continue;

    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    cookies[name] = decodeURIComponent(value);
  }

  return cookies;
}


function createSessionSignature(accessToken, startedAt) {
  const secret = process.env.SESSION_SECRET;

  if (!secret) {
    throw new Error("SESSION_SECRET is not configured.");
  }

  return crypto
    .createHmac("sha256", secret)
    .update(`${accessToken}.${startedAt}`)
    .digest("hex");
}


function safeEqual(a, b) {
  if (!a || !b) return false;

  const first = Buffer.from(a);
  const second = Buffer.from(b);

  if (first.length !== second.length) {
    return false;
  }

  return crypto.timingSafeEqual(first, second);
}


async function authenticate(req) {
  try {
    const cookies = parseCookies(req);

    const accessToken = cookies.eazyfi_access_token;
    const startedAt = cookies.eazyfi_session_started;
    const signature = cookies.eazyfi_session_signature;

    if (!accessToken || !startedAt || !signature) {
      return {
        authenticated: false,
        reason: "missing_session"
      };
    }

    const started = Number(startedAt);

    if (!Number.isFinite(started)) {
      return {
        authenticated: false,
        reason: "invalid_session_time"
      };
    }

    const age = Date.now() - started;

    if (age < 0 || age > SESSION_DURATION_MS) {
      return {
        authenticated: false,
        reason: "session_expired"
      };
    }

    const expectedSignature = createSessionSignature(
      accessToken,
      startedAt
    );

    if (!safeEqual(signature, expectedSignature)) {
      return {
        authenticated: false,
        reason: "invalid_session_signature"
      };
    }

    /*
     * Verify the Supabase access token against Supabase Auth.
     *
     * We do not trust user information supplied by the browser.
     */
    const authSupabase = createAuthSupabase();

    const {
      data: userData,
      error: userError
    } = await authSupabase.auth.getUser(accessToken);

    if (userError || !userData?.user) {
      console.warn(
        "EazyFi authentication failed: invalid Supabase user."
      );

      return {
        authenticated: false,
        reason: "invalid_access_token"
      };
    }

    const user = userData.user;

    /*
     * Find the EazyFi agent attached to this Supabase Auth user.
     *
     * The browser never gets to choose this agent_id.
     */
    const supabase = createSupabase();

    const {
      data: agent,
      error: agentError
    } = await supabase
      .from("agents")
      .select(
        "id, user_id, agent_id, agent_name, phone, terminal_id, account_locked"
      )
      .eq("user_id", user.id)
      .maybeSingle();

    if (agentError) {
      console.error(
        "EazyFi agent lookup failed:",
        agentError.message
      );

      return {
        authenticated: false,
        reason: "agent_lookup_failed"
      };
    }

    if (!agent) {
      return {
        authenticated: false,
        reason: "agent_not_found"
      };
    }

    /*
     * A locked agent cannot continue using the portal.
     */
    if (agent.account_locked) {
      return {
        authenticated: false,
        reason: "account_locked"
      };
    }

    /*
     * Return only server-trusted identity information.
     */
    return {
      authenticated: true,

      user: {
        id: user.id,
        email: user.email || null
      },

      agent: {
        id: agent.id,
        agent_id: agent.agent_id,
        agent_name: agent.agent_name,
        phone: agent.phone,
        terminal_id: agent.terminal_id
      },

      session: {
        startedAt: started,
        expiresAt: started + SESSION_DURATION_MS,
        remainingMs: Math.max(
          0,
          SESSION_DURATION_MS - age
        )
      }
    };

  } catch (error) {
    console.error(
      "EazyFi authentication error:",
      error.message
    );

    return {
      authenticated: false,
      reason: "authentication_error"
    };
  }
}


function requireAuthentication(handler) {
  return async (req, res) => {

    const auth = await authenticate(req);

    if (!auth.authenticated) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
        reason: auth.reason
      });
    }

    /*
     * Attach trusted identity to the request.
     *
     * API routes should use:
     *
     * req.eazyfi.user
     * req.eazyfi.agent
     *
     * Never trust agent_id from req.body or req.query
     * when determining ownership.
     */
    req.eazyfi = auth;

    return handler(req, res);
  };
}


module.exports = {
  authenticate,
  requireAuthentication,
  SESSION_DURATION_MS
};
