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
    const { data: sales, error } = await supabase
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
      .eq("status", "success")
      .order("created_at", { ascending: false })
      .limit(limit);

    if (error) {
      throw error;
    }

    const formattedSales = (sales || []).map((sale) => ({
      id: sale.id,
      paystack_ref: sale.paystack_ref,
      agent_id: sale.agent_id,
      agent_name: sale.agents?.agent_name || null,
      package_id: sale.package_id,
      package_name: sale.packages?.package_name || null,
      package_price_in_pesewas:
        sale.packages?.price_in_pesewas || null,
      customer_phone: sale.customer_phone,
      amount_paid: sale.amount_paid,
      voucher_code: sale.voucher_code,
      sms_status: sale.sms_status,
      status: sale.status,
      created_at: sale.created_at
    }));

    return res.status(200).json({
      success: true,
      sales: formattedSales,
      count: formattedSales.length,
      limit
    });
  } catch (error) {
    console.error(
      "[EazyFi] List-sales error:",
      error?.message || error
    );

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
};
