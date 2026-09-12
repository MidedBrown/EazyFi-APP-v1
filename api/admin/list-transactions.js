const { createSupabase } = require("../../lib/supabase");
const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  timingSafeEqualStrings
} = require("../../lib/security");

function getLimit(req) {
  const rawLimit = req.query?.limit;

  if (rawLimit === undefined) {
    return 50;
  }

  const limit = Number(rawLimit);

  if (!Number.isInteger(limit) || limit < 1) {
    return 50;
  }

  return Math.min(limit, 100);
}

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

  const limit = getLimit(req);
  const supabase = createSupabase();

  try {
    const { data: transactions, error } = await supabase
      .from("transactions")
      .select(`
        id,
        paystack_ref,
        agent_id,
        package_id,
        customer_phone,
        amount_paid,
        voucher_code,
        sms_status,
        status,
        created_at,
        agents (
          agent_name
        ),
        packages (
          package_name,
          price_in_pesewas
        )
      `)
      .order("created_at", { ascending: false })
      .limit(limit);

    if (error) {
      throw error;
    }

    const formattedTransactions = (transactions || []).map(
      (transaction) => ({
        id: transaction.id,
        paystack_ref: transaction.paystack_ref,
        agent_id: transaction.agent_id,
        agent_name: transaction.agents?.agent_name || null,
        package_id: transaction.package_id,
        package_name: transaction.packages?.package_name || null,
        package_price_in_pesewas:
          transaction.packages?.price_in_pesewas || null,
        customer_phone: transaction.customer_phone,
        amount_paid: transaction.amount_paid,
        voucher_code: transaction.voucher_code,
        sms_status: transaction.sms_status,
        status: transaction.status,
        created_at: transaction.created_at
      })
    );

    return res.status(200).json({
      success: true,
      transactions: formattedTransactions,
      count: formattedTransactions.length,
      limit
    });
  } catch (error) {
    console.error(
      "[EazyFi] List-transactions error:",
      error?.message || error
    );

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
};
