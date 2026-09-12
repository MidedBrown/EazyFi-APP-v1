const {
  createSupabase
} = require("../../lib/supabase");

const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  normalizeText,
  normalizePhone,
  isNonEmptyString,
  isReasonableBodySize,
  logServerError
} = require("../../lib/security");

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk;

      if (
        Buffer.byteLength(body, "utf8") >
        20 * 1024
      ) {
        reject(
          new Error("Request body too large.")
        );

        req.destroy();
      }
    });

    req.on("end", () => {
      try {
        resolve(
          body
            ? JSON.parse(body)
            : {}
        );
      } catch {
        reject(
          new Error("Invalid JSON body.")
        );
      }
    });

    req.on("error", reject);
  });
}

function isAdminRequest(req) {
  /*
   * The admin endpoint requires a private
   * server-to-server authorization value.
   *
   * ADMIN_API_KEY must be stored only in Vercel
   * Environment Variables.
   */
  const configuredKey =
    process.env.ADMIN_API_KEY;

  const suppliedKey =
    req.headers["x-admin-api-key"];

  if (
    !configuredKey ||
    typeof suppliedKey !== "string"
  ) {
    return false;
  }

  return suppliedKey === configuredKey;
}

module.exports = async function handler(req, res) {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "POST")) {
    return;
  }

  if (!isAdminRequest(req)) {
    return sendError(
      res,
      403,
      "Admin authorization required."
    );
  }

  if (
    !isReasonableBodySize(
      req,
      20 * 1024
    )
  ) {
    return sendError(
      res,
      413,
      "Request body is too large."
    );
  }

  try {
    const body =
      await parseBody(req);

    const email =
      normalizeText(body.email);

    const password =
      typeof body.password === "string"
        ? body.password
        : "";

    const agentId =
      normalizeText(body.agent_id);

    const agentName =
      normalizeText(body.agent_name);

    const phone =
      normalizePhone(body.phone);

    const terminalId =
      normalizeText(body.terminal_id);

    if (
      !isNonEmptyString(email) ||
      !email.includes("@")
    ) {
      return sendError(
        res,
        400,
        "A valid email is required."
      );
    }

    if (
      password.length < 8
    ) {
      return sendError(
        res,
        400,
        "Password must contain at least 8 characters."
      );
    }

    if (
      !isNonEmptyString(agentId)
    ) {
      return sendError(
        res,
        400,
        "Agent ID is required."
      );
    }

    if (
      !isNonEmptyString(agentName)
    ) {
      return sendError(
        res,
        400,
        "Agent name is required."
      );
    }

    if (
      agentId.length > 100
    ) {
      return sendError(
        res,
        400,
        "Agent ID is too long."
      );
    }

    if (
      agentName.length > 150
    ) {
      return sendError(
        res,
        400,
        "Agent name is too long."
      );
    }

    const supabase =
      createSupabase();

    /*
     * Check Agent ID before creating the
     * Supabase Auth user.
     */
    const {
      data: existingAgent,
      error: existingAgentError
    } = await supabase
      .from("agents")
      .select("id")
      .eq(
        "agent_id",
        agentId
      )
      .maybeSingle();

    if (existingAgentError) {
      logServerError(
        "admin-create-agent-check",
        existingAgentError
      );

      return sendError(
        res,
        500,
        "Unable to check Agent ID."
      );
    }

    if (existingAgent) {
      return sendError(
        res,
        409,
        "That Agent ID already exists."
      );
    }

    /*
     * Create the authentication account.
     */
    const {
      data: authData,
      error: authError
    } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true
    });

    if (authError) {
      logServerError(
        "admin-create-auth-user",
        authError
      );

      return sendError(
        res,
        400,
        "Unable to create agent login."
      );
    }

    if (!authData?.user?.id) {
      return sendError(
        res,
        500,
        "Agent login was created without a user ID."
      );
    }

    /*
     * Create the matching application-level
     * agent record.
     */
    const {
      data: agent,
      error: agentError
    } = await supabase
      .from("agents")
      .insert({
        user_id:
          authData.user.id,

        agent_id:
          agentId,

        agent_name:
          agentName,

        phone:
          phone || null,

        terminal_id:
          terminalId || null
      })
      .select(
        "id, user_id, agent_id, agent_name, phone, terminal_id, created_at"
      )
      .single();

    if (agentError) {
      logServerError(
        "admin-create-agent-record",
        agentError
      );

      /*
       * If the application record fails,
       * remove the Auth user so we don't leave
       * an orphaned login behind.
       */
      try {
        await supabase.auth.admin.deleteUser(
          authData.user.id
        );
      } catch (cleanupError) {
        logServerError(
          "admin-create-agent-cleanup",
          cleanupError
        );
      }

      return sendError(
        res,
        500,
        "Unable to create agent profile."
      );
    }

    return res.status(201).json({
      success: true,

      message:
        "Agent created successfully.",

      agent: {
        id: agent.id,
        agent_id:
          agent.agent_id,
        agent_name:
          agent.agent_name,
        phone:
          agent.phone,
        terminal_id:
          agent.terminal_id
      }
    });

  } catch (error) {
    logServerError(
      "admin-create-agent",
      error
    );

    if (
      error.message ===
      "Invalid JSON body."
    ) {
      return sendError(
        res,
        400,
        "Invalid JSON request."
      );
    }

    if (
      error.message ===
      "Request body too large."
    ) {
      return sendError(
        res,
        413,
        "Request body is too large."
      );
    }

    return sendError(
      res,
      500,
      "Unable to create agent."
    );
  }
};
