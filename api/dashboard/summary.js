const { requireAuthentication } = require("../../lib/authenticate");
const {
  sendError,
  requireMethod,
  applySecurityHeaders,
  logServerError
} = require("../../lib/security");

module.exports = requireAuthentication(async (req, res, auth) => {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "GET")) {
    return;
  }

  try {
    const supabase = auth.supabase;
    const agentId = auth.agent.agent_id;

    const [
      packagesResult,
      availableResult,
      usedResult,
      successfulSalesResult,
      todaySalesResult,
      todayTransactionsResult
    ] = await Promise.all([
      supabase
        .from("packages")
        .select("id, package_name, price_in_pesewas, created_at")
        .eq("agent_id", agentId)
        .order("price_in_pesewas", { ascending: true }),

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
        .eq("status", "success"),

      supabase
        .from("transactions")
        .select("amount_paid")
        .eq("agent_id", agentId)
        .eq("status", "success")
        .gte(
          "created_at",
          new Date(new Date().setHours(0, 0, 0, 0)).toISOString()
        ),

      supabase
        .from("transactions")
        .select("id", { count: "exact", head: true })
        .eq("agent_id", agentId)
        .eq("status", "success")
        .gte(
          "created_at",
          new Date(new Date().setHours(0, 0, 0, 0)).toISOString()
        )
    ]);

    const results = [
      packagesResult,
      availableResult,
      usedResult,
      successfulSalesResult,
      todaySalesResult,
      todayTransactionsResult
    ];

    for (const result of results) {
      if (result.error) {
        throw result.error;
      }
    }

    const todaySales =
      (todaySalesResult.data || []).reduce(
        (total, transaction) =>
          total + Number(transaction.amount_paid || 0),
        0
      ) / 100;

    const totalSales =
      (await supabase
        .from("transactions")
        .select("amount_paid")
        .eq("agent_id", agentId)
        .eq("status", "success")
      ).data || [];

    const totalSalesAmount =
      totalSales.reduce(
        (total, transaction) =>
          total + Number(transaction.amount_paid || 0),
        0
      ) / 100;

    return res.status(200).json({
      success: true,

      agent: {
        agent_id: auth.agent.agent_id,
        agent_name: auth.agent.agent_name,
        phone: auth.agent.phone,
        terminal_id: auth.agent.terminal_id,
        wallet_balance: auth.agent.wallet_balance
      },

      packages: packagesResult.data || [],

      stats: {
        available_vouchers: availableResult.count || 0,
        used_vouchers: usedResult.count || 0,
        successful_sales: successfulSalesResult.count || 0
      },

      totalSales: totalSalesAmount,
      todaySales,
      todayTransactions: todayTransactionsResult.count || 0,

      session: {
        started_at: auth.session.startedAt,
        expires_at: auth.session.expiresAt,
        remaining_seconds: auth.session.remainingSeconds
      }
    });
  } catch (error) {
    logServerError("GET /api/dashboard/summary failed", error);
    return sendError(res, 500, "Unable to load dashboard summary.");
  }
});
