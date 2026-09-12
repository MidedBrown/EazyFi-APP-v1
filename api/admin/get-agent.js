const { createSupabase } = require("../../lib/supabase");
const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  normalizeText,
  isNonEmptyString,
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
    const agentId = normalizeText(req.query?.agent_id);

    if (!isNonEmptyString(agentId)) {
      return sendError(res, 400, "agent_id is required.");
    }

    const supabase = createSupabase();

    const { data: agent, error: agentError } = await supabase
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
      .eq("agent_id", agentId)
      .maybeSingle();

    if (agentError) {
      logServerError("admin/get-agent agent", agentError);
      return sendError(res, 500, "Unable to load agent.");
    }

    if (!agent) {
      return sendError(res, 404, "Agent not found.");
    }

    const [
      packagesResult,
      availableVouchersResult,
      usedVouchersResult,
      salesResult
    ] = await Promise.all([
      supabase
        .from("packages")
        .select("id, package_name, price_in_pesewas, created_at")
        .eq("agent_id", agentId)
        .order("created_at", { ascending: false }),

      supabase
        .from("vouchers")
        .select("id", { count: "exact", head: true })
        .eq("agent_id", agentId)
        .eq("status", "available"),

      supabase
        .from("vouchers")
        .select("id", { count: "exact", head: true })
        .eq("agent_id", agentId)
        .eq("status", "used"),

      supabase
        .from("transactions")
        .select("id", { count: "exact", head: true })
        .eq("agent_id", agentId)
        .eq("status", "success")
    ]);

    if (packagesResult.error) {
      logServerError("admin/get-agent packages", packagesResult.error);
      return sendError(res, 500, "Unable to load agent packages.");
    }

    if (availableVouchersResult.error) {
      logServerError(
        "admin/get-agent available vouchers",
        availableVouchersResult.error
      );
      return sendError(res, 500, "Unable to load voucher statistics.");
    }

    if (usedVouchersResult.error) {
      logServerError(
        "admin/get-agent used vouchers",
        usedVouchersResult.error
      );
      return sendError(res, 500, "Unable to load voucher statistics.");
    }

    if (salesResult.error) {
      logServerError(
        "admin/get-agent sales",
        salesResult.error
      );
      return sendError(res, 500, "Unable to load sales statistics.");
    }

    return res.status(200).json({
      success: true,
      agent,
      packages: packagesResult.data || [],
      stats: {
        available_vouchers: availableVouchersResult.count || 0,
        used_vouchers: usedVouchersResult.count || 0,
        successful_sales: salesResult.count || 0
      }
    });
  } catch (error) {
    logServerError("admin/get-agent", error);
    return sendError(res, 500, "Unable to load agent details.");
  }
};
