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
      throw error;
    }

    const formattedVouchers = (vouchers || []).map((voucher) => ({
      id: voucher.id,
      agent_id: voucher.agent_id,
      agent_name: voucher.agents?.agent_name || null,
      package_id: voucher.package_id,
      package_name: voucher.packages?.package_name || null,
      price_in_pesewas: voucher.packages?.price_in_pesewas || null,
      voucher_code: voucher.voucher_code,
      status: voucher.status,
      used_at: voucher.used_at,
      created_at: voucher.created_at
    }));

    return res.status(200).json({
      success: true,
      vouchers: formattedVouchers
    });
  } catch (error) {
    console.error(
      "[EazyFi] List-vouchers error:",
      error?.message || error
    );

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
};
