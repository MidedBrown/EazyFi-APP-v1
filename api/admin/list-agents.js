const { createSupabase } = require("../../lib/supabase");
const {
  requireAdminAuthentication
} = require("../../lib/admin-auth");

const {
  sendError,
  requireMethod,
  applySecurityHeaders,
  logServerError
} = require("../../lib/security");

module.exports = async (req, res) => {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "GET")) {
    return;
  }

  const admin = await requireAdminAuthentication(req, res);

  if (!admin) {
    return;
  }

  try {
    const supabase = createSupabase();

    const { data, error } = await supabase
      .from("agents")
      .select(
        "id, agent_id, agent_name, phone, terminal_id, wallet_balance, login_failed_attempts, account_locked, account_locked_at, account_locked_reason, created_at"
      )
      .order("created_at", { ascending: false });

    if (error) {
      throw error;
    }

    return res.status(200).json({
      success: true,
      agents: data || [],
      count: (data || []).length
    });
  } catch (error) {
    logServerError(
      "GET /api/admin/list-agents failed",
      error
    );

    return sendError(
      res,
      500,
      "Unable to load agents."
    );
  }
};
