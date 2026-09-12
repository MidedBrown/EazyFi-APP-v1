const { createSupabase } = require("../../lib/supabase");
const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  isNonEmptyString,
  timingSafeEqualStrings
} = require("../../lib/security");

module.exports = async function handler(req, res) {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "GET")) return;

  const configuredAdminKey = process.env.ADMIN_API_KEY || "";
  const suppliedAdminKey = req.headers["x-admin-api-key"] || "";

  if (
    !configuredAdminKey ||
    !timingSafeEqualStrings(suppliedAdminKey, configuredAdminKey)
  ) {
    return sendError(res, 401, "Unauthorized.");
  }

  const agentId =
    typeof req.query?.agent_id === "string"
      ? req.query.agent_id.trim()
      : "";

  if (!isNonEmptyString(agentId)) {
    return sendError(res, 400, "Agent ID is required.");
  }

  const supabase = createSupabase();

  try {
    const { data: agent, error: agentError } = await supabase
      .from("agents")
      .select(
        "id, user_id, agent_id, agent_name, phone, terminal_id, wallet_balance, login_failed_attempts, account_locked, account_locked_at, account_locked_reason, created_at"
      )
      .eq("agent_id", agentId)
      .maybeSingle();

    if (agentError) {
      throw agentError;
    }

    if (!agent) {
      return sendError(res, 404, "Agent not found.");
    }

    const { data: packages, error: packagesError } =
      await supabase
        .from("packages")
        .select(
          "id, agent_id, package_name, price_in_pesewas, created_at"
        )
        .eq("agent_id", agentId)
        .order("created_at", { ascending: false });

    if (packagesError) {
      throw packagesError;
    }

    const [
      availableVouchersResult,
      usedVouchersResult,
      successfulSalesResult
    ] = await Promise.all([
      supabase
        .from("vouchers")
        .select("id", {
          count: "exact",
          head: true
        })
        .eq("agent_id", agentId)
        .eq("status", "available"),

      supabase
        .from("vouchers")
        .select("id", {
          count: "exact",
          head: true
        })
        .eq("agent_id", agentId)
        .eq("status", "used"),

      supabase
        .from("transactions")
        .select("id", {
          count: "exact",
          head: true
        })
        .eq("agent_id", agentId)
        .eq("status", "success")
    ]);

    const countResults = [
      availableVouchersResult,
      usedVouchersResult,
      successfulSalesResult
    ];

    const failedResult = countResults.find(
      (result) => result.error
    );

    if (failedResult) {
      throw failedResult.error;
    }

    return res.status(200).json({
      success: true,
      agent,
      packages: packages || [],
      stats: {
        available_vouchers:
          availableVouchersResult.count || 0,
        used_vouchers:
          usedVouchersResult.count || 0,
        successful_sales:
          successfulSalesResult.count || 0
      }
    });
  } catch (error) {
    console.error(
      "[EazyFi] Get-agent error:",
      error?.message || error
    );

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
};
