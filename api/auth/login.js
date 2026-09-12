const crypto = require("crypto");

const {
  createAuthSupabase,
  createSupabase
} = require("../../lib/supabase");

const {
  checkLoginRateLimit
} = require("../../lib/rate-limit");

const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  isNonEmptyString,
  logServerError
} = require("../../lib/security");


const SESSION_DURATION_MS =
  30 * 60 * 1000; // 30 minutes

const MAX_FAILED_ATTEMPTS = 3;


/*
 * Create the signature used to protect our EazyFi
 * session cookies.
 */
function createSessionSignature(
  accessToken,
  startedAt
) {
  const secret =
    process.env.SESSION_SECRET;

  if (!secret) {
    throw new Error(
      "SESSION_SECRET is not configured."
    );
  }

  return crypto
    .createHmac(
      "sha256",
      secret
    )
    .update(
      `${accessToken}.${startedAt}`
    )
    .digest("hex");
}


/*
 * Cookie helper.
 */
function serializeCookie(
  name,
  value,
  options = {}
) {
  let cookie =
    `${name}=${encodeURIComponent(value)}`;

  cookie += "; Path=/";

  if (options.maxAge !== undefined) {
    cookie += `; Max-Age=${options.maxAge}`;
  }

  if (options.httpOnly !== false) {
    cookie += "; HttpOnly";
  }

  if (options.secure !== false) {
    cookie += "; Secure";
  }

  cookie += "; SameSite=Lax";

  return cookie;
}


/*
 * Clear all EazyFi authentication cookies.
 */
function clearAuthCookies() {
  const maxAge = 0;

  return [
    serializeCookie(
      "eazyfi_access_token",
      "",
      { maxAge }
    ),

    serializeCookie(
      "eazyfi_refresh_token",
      "",
      { maxAge }
    ),

    serializeCookie(
      "eazyfi_session_started",
      "",
      { maxAge }
    ),

    serializeCookie(
      "eazyfi_session_signature",
      "",
      { maxAge }
    )
  ];
}


/*
 * Extract email/password safely.
 */
function getCredentials(req) {
  if (
    !req.body ||
    typeof req.body !== "object" ||
    Array.isArray(req.body)
  ) {
    return null;
  }

  const email =
    typeof req.body.email === "string"
      ? req.body.email.trim().toLowerCase()
      : "";

  const password =
    typeof req.body.password === "string"
      ? req.body.password
      : "";

  if (
    !isNonEmptyString(email) ||
    !isNonEmptyString(password)
  ) {
    return null;
  }

  return {
    email,
    password
  };
}


/*
 * Find the EazyFi agent belonging to a Supabase
 * Auth user.
 */
async function findAgentByUserId(
  supabase,
  userId
) {
  const {
    data,
    error
  } = await supabase
    .from("agents")
    .select(
      `
      id,
      user_id,
      agent_id,
      agent_name,
      phone,
      terminal_id,
      account_locked,
      login_failed_attempts
      `
    )
    .eq("user_id", userId)
    .maybeSingle();

  if (error) {
    throw error;
  }

  return data;
}


/*
 * Find an agent by email through Supabase Auth.
 *
 * We use the Auth Admin API only on the trusted server.
 *
 * This does NOT expose the user's existence to the browser.
 */
async function findAuthUserByEmail(
  supabase,
  email
) {
  let page = 1;

  const perPage = 1000;

  /*
   * Supabase's admin API is server-only.
   *
   * We search pages until we find the matching email
   * or there are no more users.
   */
  while (true) {
    const {
      data,
      error
    } = await supabase.auth.admin.listUsers({
      page,
      perPage
    });

    if (error) {
      throw error;
    }

    const users =
      data?.users || [];

    const matchingUser =
      users.find(
        user =>
          typeof user.email === "string" &&
          user.email.toLowerCase() === email
      );

    if (matchingUser) {
      return matchingUser;
    }

    if (
      users.length < perPage
    ) {
      return null;
    }

    page += 1;
  }
}


/*
 * Increment the failed-login counter.
 */
async function recordFailedAttempt(
  supabase,
  agent
) {
  const current =
    Number(
      agent.login_failed_attempts || 0
    );

  const next =
    current + 1;

  const shouldLock =
    next >= MAX_FAILED_ATTEMPTS;

  const update = {
    login_failed_attempts:
      shouldLock
        ? MAX_FAILED_ATTEMPTS
        : next
  };

  if (shouldLock) {
    update.account_locked = true;
    update.account_locked_at =
      new Date().toISOString();
    update.account_locked_reason =
      "Three failed login attempts";
  }

  const {
    error
  } = await supabase
    .from("agents")
    .update(update)
    .eq("id", agent.id);

  if (error) {
    throw error;
  }

  return {
    failedAttempts: next,
    locked: shouldLock
  };
}


/*
 * Reset the failed-login counter after successful
 * authentication.
 */
async function resetFailedAttempts(
  supabase,
  agent
) {
  const {
    error
  } = await supabase
    .from("agents")
    .update({
      login_failed_attempts: 0,
      account_locked: false,
      account_locked_at: null,
      account_locked_reason: null
    })
    .eq("id", agent.id);

  if (error) {
    throw error;
  }
}


/*
 * Main login endpoint.
 */
module.exports = async function handler(
  req,
  res
) {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "POST")) {
    return;
  }

  /*
   * Fast IP protection.
   *
   * This prevents a single IP from hammering the
   * login endpoint continuously.
   */
  const rateLimit =
    checkLoginRateLimit(req);

  res.setHeader(
    "Retry-After",
    String(
      rateLimit.retryAfterSeconds
    )
  );

  if (!rateLimit.allowed) {
    return sendError(
      res,
      429,
      "Too many login attempts. Please try again later."
    );
  }


  const credentials =
    getCredentials(req);

  if (!credentials) {
    return sendError(
      res,
      400,
      "Email and password are required."
    );
  }


  const {
    email,
    password
  } = credentials;


  try {
    /*
     * Trusted backend database client.
     */
    const supabase =
      createSupabase();


    /*
     * Find the Auth user so we can determine whether
     * this EazyFi account is already locked.
     *
     * This lookup happens only after the IP limiter.
     */
    const authUser =
      await findAuthUserByEmail(
        supabase,
        email
      );


    /*
     * If the email isn't associated with an Auth user,
     * still return the same generic login failure.
     *
     * We do not tell the browser that the email
     * doesn't exist.
     */
    if (!authUser) {
      return sendError(
        res,
        401,
        "Invalid email or password."
      );
    }


    /*
     * Find the EazyFi agent.
     */
    const agent =
      await findAgentByUserId(
        supabase,
        authUser.id
      );


    /*
     * No EazyFi agent is attached to this Auth user.
     */
    if (!agent) {
      return sendError(
        res,
        401,
        "Invalid email or password."
      );
    }


    /*
     * Check persistent account lock BEFORE attempting
     * another password authentication.
     */
    if (agent.account_locked) {
      res.setHeader(
        "Set-Cookie",
        clearAuthCookies()
      );

      return sendError(
        res,
        423,
        "This account is locked. Please contact the administrator."
      );
    }


    /*
     * Perform the actual Supabase password login.
     */
    const authSupabase =
      createAuthSupabase();

    const {
      data: authData,
      error: authError
    } =
      await authSupabase.auth
        .signInWithPassword({
          email,
          password
        });


    /*
     * Wrong password.
     */
    if (
      authError ||
      !authData?.user ||
      !authData?.session
    ) {
      const result =
        await recordFailedAttempt(
          supabase,
          agent
        );

      /*
       * Deliberately do NOT reveal the exact
       * number of attempts remaining.
       */
      if (result.locked) {
        return sendError(
          res,
          423,
          "This account is now locked. Please contact the administrator."
        );
      }

      return sendError(
        res,
        401,
        "Invalid email or password."
      );
    }


    /*
     * Supabase authentication succeeded.
     *
     * Reset the persistent failed-login counter.
     */
    await resetFailedAttempts(
      supabase,
      agent
    );


    const accessToken =
      authData.session.access_token;

    const refreshToken =
      authData.session.refresh_token;

    const startedAt =
      Date.now().toString();


    const signature =
      createSessionSignature(
        accessToken,
        startedAt
      );


    const maxAge =
      Math.floor(
        SESSION_DURATION_MS / 1000
      );


    /*
     * Create our EazyFi session cookies.
     *
     * The tokens are HttpOnly, meaning browser
     * JavaScript cannot read them.
     */
    const cookies = [
      serializeCookie(
        "eazyfi_access_token",
        accessToken,
        { maxAge }
      ),

      serializeCookie(
        "eazyfi_refresh_token",
        refreshToken,
        { maxAge }
      ),

      serializeCookie(
        "eazyfi_session_started",
        startedAt,
        { maxAge }
      ),

      serializeCookie(
        "eazyfi_session_signature",
        signature,
        { maxAge }
      )
    ];


    res.setHeader(
      "Set-Cookie",
      cookies
    );


    /*
     * Do not return the access token or refresh token
     * to the browser JavaScript.
     */
    return res.status(200).json({
      success: true,

      agent: {
        agent_id: agent.agent_id,
        agent_name: agent.agent_name,
        phone: agent.phone
      },

      session: {
        durationSeconds:
          Math.floor(
            SESSION_DURATION_MS / 1000
          )
      }
    });


  } catch (error) {

    logServerError(
      "login",
      error
    );

    /*
     * Clear authentication cookies if something
     * unexpected happened during login.
     */
    res.setHeader(
      "Set-Cookie",
      clearAuthCookies()
    );

    return sendError(
      res,
      500,
      "Unable to complete login. Please try again."
    );
  }
};
