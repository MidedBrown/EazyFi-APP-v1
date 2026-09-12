const {
  requireAuthentication
} = require("../../lib/authenticate");

const {
  createSupabase
} = require("../../lib/supabase");

const {
  applySecurityHeaders,
  requireMethod,
  logServerError
} = require("../../lib/security");

module.exports = requireAuthentication(
  async function handler(req, res) {
    applySecurityHeaders(res);

    if (!requireMethod(req, res, "GET")) {
      return;
    }

    try {
      const agentId =
        req.eazyfi.agent.agent_id;

      const supabase = createSupabase();

      const {
        data: vouchers,
        error
      } = await supabase
        .from("vouchers")
        .select(`
          id,
          package_id,
          voucher_code,
          status,
          used_at,
          created_at,
          packages (
            package_name,
            price_in_pesewas
          )
        `)
        .eq("agent_id", agentId)
        .order("created_at", {
          ascending: false
        });

      if (error) {
        logServerError(
          "voucher-list",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Unable to load vouchers."
        });
      }

      return res.status(200).json({
        success: true,
        vouchers: vouchers || []
      });

    } catch (error) {
      logServerError(
        "voucher-list-handler",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load vouchers."
      });
    }
  }
);
