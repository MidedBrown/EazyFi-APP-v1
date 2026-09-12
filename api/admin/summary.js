const { createSupabase } = require("../../lib/supabase");
const {
  applySecurityHeaders,
  requireMethod,
  sendError,
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

  const supabase = createSupabase();

  try {
    const [
      agentsResult,
      lockedAgentsResult,
      packagesResult,
      vouchersResult,
      availableVouchersResult,
      usedVouchersResult,
      successfulTransactionsResult,
      outOfStockTransactionsResult
    ] = await Promise.all([
      supabase
        .from("agents")
        .select("id", { count: "exact", head: true }),

      supabase
        .from("agents")
        .select("id", { count: "exact", head: true })
        .eq("account_locked", true),

      supabase
        .from("packages")
        .select("id", { count: "exact", head: true }),

      supabase
        .from("vouchers")
        .select("id", { count: "exact", head: true }),

      supabase
        .from("vouchers")
        .select("id", { count: "exact", head: true })
        .eq("status", "available"),

      supabase
        .from("vouchers")
        .select("id", { count: "exact", head: true })
        .eq("status", "used"),

      supabase
        .from("transactions")
        .select("id", { count: "exact", head: true })
        .eq("status", "success"),

      supabase
        .from("transactions")
        .select("id", { count: "exact", head: true })
        .eq("status", "out_of_stock")
    ]);

    const results = [
      agentsResult,
      lockedAgentsResult,
      packagesResult,
      vouchersResult,
      availableVouchersResult,
      usedVouchersResult,
      successfulTransactionsResult,
      outOfStockTransactionsResult
    ];

    const failedResult = results.find((result) => result.error);

    if (failedResult) {
      throw failedResult.error;
    }

    return res.status(200).json({
      success: true,
      summary: {
        total_agents: agentsResult.count || 0,
        locked_agents: lockedAgentsResult.count || 0,
        total_packages: packagesResult.count || 0,
        total_vouchers: vouchersResult.count || 0,
        available_vouchers: availableVouchersResult.count || 0,
        used_vouchers: usedVouchersResult.count || 0,
        successful_transactions:
          successfulTransactionsResult.count || 0,
        out_of_stock_transactions:
          outOfStockTransactionsResult.count || 0
      }
    });
  } catch (error) {
    console.error(
      "[EazyFi] Admin summary error:",
      error?.message || error
    );

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
};
