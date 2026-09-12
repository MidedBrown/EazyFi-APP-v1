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

    const { data: vouchers, error } = await supabase
      .from("vouchers")
      .select(`
        id,
        agent_id,
        package_id,
        voucher_code,
        status,
        used_at,
        created_at,
        agents (
          agent_name
        ),
        packages (
          package_name,
          price_in_pesewas
        )
      `)
      .order("created_at", { ascending: false });

    if (error) {
      logServerError("admin/list-vouchers", error);
      return sendError(res, 500, "Unable to load vouchers.");
    }

    const formattedVouchers = vouchers.map((item) => ({
      id: item.id,
      agent_id: item.agent_id,
      agent_name: item.agents?.agent_name || null,
      package_id: item.package_id,
      package_name: item.packages?.package_name || null,
      price_in_pesewas: item.packages?.price_in_pesewas || null,
      voucher_code: item.voucher_code,
      status: item.status,
      used_at: item.used_at,
      created_at: item.created_at
    }));

    return res.status(200).json({
      success: true,
      count: formattedVouchers.length,
      vouchers: formattedVouchers
    });
  } catch (error) {
    logServerError("admin/list-vouchers", error);
    return sendError(res, 500, "Unable to load vouchers.");
  }
};
