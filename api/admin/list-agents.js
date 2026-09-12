const { createSupabase } = require("../../lib/supabase");
const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  logServerError
} = require("../../lib/security");

function isAdminRequest(req) {
  const configuredKey = process.env.ADMIN_API_KEY;
  const suppliedKey = req.headers["x-admin-api-key"];

  if (!configuredKey || typeof suppliedKey !== "string") {
    return false;
  }

  return suppliedKey === configuredKey;
}

module.exports = async function handler(req, res) {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "GET")) {
    return;
  }

  if (!isAdminRequest(req)) {
    return sendError(res, 403, "Forbidden.");
  }

  try {
    const supabase = createSupabase();

    const { data: agents, error } = await supabase
      .from("agents")
      .select(`
        id,
        agent_id,
        agent_name,
        phone,
        terminal_id,
        wallet_balance,
        login_failed_attempts,
        account_locked,
        account_locked_at,
        account_locked_reason,
        created_at
      `)
      .order("created_at", { ascending: false });

    if (error) {
      logServerError("admin/list-agents", error);
      return sendError(res, 500, "Unable to load agents.");
    }

    return res.status(200).json({
      success: true,
      count: agents.length,
      agents
    });
  } catch (error) {
    logServerError("admin/list-agents", error);
    return sendError(res, 500, "Unable to load agents.");
  }
};
