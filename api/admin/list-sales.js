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

function getLimit(req) {
  const requested = Number(req.query?.limit);

  if (!Number.isInteger(requested) || requested <= 0) {
    return 50;
  }

  return Math.min(requested, 100);
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
    const limit = getLimit(req);

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
      logServerError("admin/list-sales", error);
      return sendError(res, 500, "Unable to load sales.");
    }

    const formattedSales = sales.map((item) => ({
      id: item.id,
      paystack_ref: item.paystack_ref,
      agent_id: item.agent_id,
      agent_name: item.agents?.agent_name || null,
      package_id: item.package_id,
      package_name: item.packages?.package_name || null,
      package_price_in_pesewas:
        item.packages?.price_in_pesewas || null,
      customer_phone: item.customer_phone,
      amount_paid: item.amount_paid,
      voucher_code: item.voucher_code,
      sms_status: item.sms_status,
      status: item.status,
      created_at: item.created_at
    }));

    return res.status(200).json({
      success: true,
      count: formattedSales.length,
      sales: formattedSales
    });
  } catch (error) {
    logServerError("admin/list-sales", error);
    return sendError(res, 500, "Unable to load sales.");
  }
};
