const { createSupabase } = require("../../lib/supabase");
const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  isNonEmptyString,
  isReasonableBodySize,
  timingSafeEqualStrings
} = require("../../lib/security");

function isValidEmail(email) {
  return (
    typeof email === "string" &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  );
}

function parseBody(req) {
  if (req.body && typeof req.body === "object") {
    return req.body;
  }

  if (typeof req.body === "string") {
    try {
      return JSON.parse(req.body);
    } catch {
      return null;
    }
  }

  return null;
}

module.exports = async function handler(req, res) {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "POST")) return;

  const configuredAdminKey = process.env.ADMIN_API_KEY || "";
  const suppliedAdminKey = req.headers["x-admin-api-key"] || "";

  if (
    !configuredAdminKey ||
    !timingSafeEqualStrings(suppliedAdminKey, configuredAdminKey)
  ) {
    return sendError(res, 401, "Unauthorized.");
  }

  if (!isReasonableBodySize(req.body, 20000)) {
    return sendError(res, 413, "Request body is too large.");
  }

  const body = parseBody(req);

  if (!body) {
    return sendError(res, 400, "Invalid JSON body.");
  }

  const email = typeof body.email === "string"
    ? body.email.trim().toLowerCase()
    : "";

  const password = typeof body.password === "string"
    ? body.password
    : "";

  const agentId = typeof body.agent_id === "string"
    ? body.agent_id.trim()
    : "";

  const agentName = typeof body.agent_name === "string"
    ? body.agent_name.trim()
    : "";

  const phone = typeof body.phone === "string"
    ? body.phone.trim()
    : null;

  const terminalId = typeof body.terminal_id === "string"
    ? body.terminal_id.trim()
    : null;

  if (!isValidEmail(email)) {
    return sendError(res, 400, "A valid email address is required.");
  }

  if (password.length < 8) {
    return sendError(
      res,
      400,
      "Password must be at least 8 characters."
    );
  }

  if (!isNonEmptyString(agentId)) {
    return sendError(res, 400, "Agent ID is required.");
  }

  if (!isNonEmptyString(agentName)) {
    return sendError(res, 400, "Agent name is required.");
  }

  const supabase = createSupabase();

  try {
    const { data: existingAgent, error: existingAgentError } =
      await supabase
        .from("agents")
        .select("id")
        .eq("agent_id", agentId)
        .maybeSingle();

    if (existingAgentError) {
      throw existingAgentError;
    }

    if (existingAgent) {
      return sendError(res, 409, "Agent ID already exists.");
    }

    const { data: authData, error: authError } =
      await supabase.auth.admin.createUser({
        email,
        password,
        email_confirm: true
      });

    if (authError || !authData?.user) {
      console.error(
        "[EazyFi] Failed to create authentication user:",
        authError?.message || "Unknown error"
      );

      return sendError(
        res,
        400,
        "Unable to create agent account."
      );
    }

    const userId = authData.user.id;

    const { data: agent, error: agentError } = await supabase
      .from("agents")
      .insert({
        user_id: userId,
        agent_id: agentId,
        agent_name: agentName,
        phone: phone || null,
        terminal_id: terminalId || null
      })
      .select(
        "id, user_id, agent_id, agent_name, phone, terminal_id, wallet_balance, created_at"
      )
      .single();

    if (agentError) {
      console.error(
        "[EazyFi] Failed to create agent record:",
        agentError.message
      );

      await supabase.auth.admin.deleteUser(userId);

      return sendError(
        res,
        500,
        "Unable to create agent record."
      );
    }

    return res.status(201).json({
      success: true,
      message: "Agent created successfully.",
      agent
    });
  } catch (error) {
    console.error(
      "[EazyFi] Create-agent error:",
      error?.message || error
    );

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
};
