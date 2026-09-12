const { createSupabase } = require("../../lib/supabase");
const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  isNonEmptyString,
  isReasonableBodySize,
  timingSafeEqualStrings
} = require("../../lib/security");

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

  const agentId =
    typeof body.agent_id === "string"
      ? body.agent_id.trim()
      : "";

  if (!isNonEmptyString(agentId)) {
    return sendError(res, 400, "Agent ID is required.");
  }

  const supabase = createSupabase();

  try {
    const { data: agent, error: findError } = await supabase
      .from("agents")
      .select("id, agent_id, agent_name, account_locked")
      .eq("agent_id", agentId)
      .maybeSingle();

    if (findError) {
      throw findError;
    }

    if (!agent) {
      return sendError(res, 404, "Agent not found.");
    }

    const { data: updatedAgent, error: updateError } =
      await supabase
        .from("agents")
        .update({
          account_locked: false,
          login_failed_attempts: 0,
          account_locked_at: null,
          account_locked_reason: null
        })
        .eq("agent_id", agentId)
        .select(
          "id, agent_id, agent_name, phone, terminal_id, wallet_balance, login_failed_attempts, account_locked, account_locked_at, account_locked_reason, created_at"
        )
        .single();

    if (updateError) {
      throw updateError;
    }

    return res.status(200).json({
      success: true,
      message: "Agent restored successfully.",
      agent: updatedAgent
    });
  } catch (error) {
    console.error(
      "[EazyFi] Restore-agent error:",
      error?.message || error
    );

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
};
