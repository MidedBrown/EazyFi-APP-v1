const {
  requireAuthentication
} = require("../../lib/authenticate");

const {
  createSupabase
} = require("../../lib/supabase");

const {
  applySecurityHeaders,
  requireMethod,
  sendError,
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
        count: available,
        error: availableError
      } = await supabase
        .from("vouchers")
        .select("id", {
          count: "exact",
          head: true
        })
        .eq("agent_id", agentId)
        .eq("status", "available");

      if (availableError) {
        logServerError(
          "voucher-count-available",
          availableError
        );

        return sendError(
          res,
          500,
          "Unable to count available vouchers."
        );
      }

      const {
        count: used,
        error: usedError
      } = await supabase
        .from("vouchers")
        .select("id", {
          count: "exact",
          head: true
        })
        .eq("agent_id", agentId)
        .eq("status", "used");

      if (usedError) {
        logServerError(
          "voucher-count-used",
          usedError
        );

        return sendError(
          res,
          500,
          "Unable to count used vouchers."
        );
      }

      return res.status(200).json({
        success: true,

        counts: {
          available: available || 0,
          used: used || 0,
          total:
            (available || 0) +
            (used || 0)
        }
      });

    } catch (error) {
      logServerError(
        "voucher-count-handler",
        error
      );

      return sendError(
        res,
        500,
        "Unable to load voucher counts."
      );
    }
  }
);
