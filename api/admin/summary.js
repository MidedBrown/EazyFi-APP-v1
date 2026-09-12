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

async function countRows(supabase, table, filters = []) {
  let query = supabase
    .from(table)
    .select("*", { count: "exact", head: true });

  for (const filter of filters) {
    query = query.eq(filter.column, filter.value);
  }

  const { count, error } = await query;

  if (error) {
    throw error;
  }

  return count || 0;
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

    const [
      totalAgents,
      lockedAgents,
      totalPackages,
      totalVouchers,
      availableVouchers,
      usedVouchers,
      successfulTransactions,
      outOfStockTransactions
    ] = await Promise.all([
      countRows(supabase, "agents"),

      countRows(supabase, "agents", [
        { column: "account_locked", value: true }
      ]),

      countRows(supabase, "packages"),

      countRows(supabase, "vouchers"),

      countRows(supabase, "vouchers", [
        { column: "status", value: "available" }
      ]),

      countRows(supabase, "vouchers", [
        { column: "status", value: "used" }
      ]),

      countRows(supabase, "transactions", [
        { column: "status", value: "success" }
      ]),

      countRows(supabase, "transactions", [
        { column: "status", value: "out_of_stock" }
      ])
    ]);

    return res.status(200).json({
      success: true,
      stats: {
        agents: {
          total: totalAgents,
          locked: lockedAgents
        },
        packages: {
          total: totalPackages
        },
        vouchers: {
          total: totalVouchers,
          available: availableVouchers,
          used: usedVouchers
        },
        transactions: {
          successful: successfulTransactions,
          out_of_stock: outOfStockTransactions
        }
      },
      generated_at: new Date().toISOString()
    });
  } catch (error) {
    logServerError("admin/summary", error);
    return sendError(res, 500, "Unable to load admin summary.");
  }
};
