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

      /*
       * Get the agent's packages.
       *
       * The server uses the authenticated agent_id.
       * The browser cannot choose another agent_id.
       */
      const {
        data: packages,
        error: packagesError
      } = await supabase
        .from("packages")
        .select(
          "id, package_name, price_in_pesewas, created_at"
        )
        .eq("agent_id", agentId)
        .order("price_in_pesewas", {
          ascending: true
        });

      if (packagesError) {
        logServerError(
          "dashboard-packages",
          packagesError
        );

        return res.status(500).json({
          success: false,
          message:
            "Unable to load dashboard packages."
        });
      }

      /*
       * Get voucher counts for this agent.
       *
       * We intentionally do not return voucher codes here.
       * Voucher codes will have their own protected endpoint.
       */
      const {
        count: availableVouchers,
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
          "dashboard-available-vouchers",
          availableError
        );

        return res.status(500).json({
          success: false,
          message:
            "Unable to load voucher information."
        });
      }

      const {
        count: usedVouchers,
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
          "dashboard-used-vouchers",
          usedError
        );

        return res.status(500).json({
          success: false,
          message:
            "Unable to load voucher information."
        });
      }

      /*
       * Count successful transactions belonging
       * to this authenticated agent.
       */
      const {
        count: successfulSales,
        error: salesError
      } = await supabase
        .from("transactions")
        .select("id", {
          count: "exact",
          head: true
        })
        .eq("agent_id", agentId)
        .eq("status", "success");

      if (salesError) {
        logServerError(
          "dashboard-sales",
          salesError
        );

        return res.status(500).json({
          success: false,
          message:
            "Unable to load sales information."
        });
      }

      return res.status(200).json({
        success: true,

        agent: {
          agent_id:
            req.eazyfi.agent.agent_id,

          agent_name:
            req.eazyfi.agent.agent_name,

          phone:
            req.eazyfi.agent.phone,

          terminal_id:
            req.eazyfi.agent.terminal_id
        },

        packages: packages || [],

        statistics: {
          available_vouchers:
            availableVouchers || 0,

          used_vouchers:
            usedVouchers || 0,

          successful_sales:
            successfulSales || 0
        },

        session: {
          expiresAt:
            req.eazyfi.session.expiresAt,

          remainingMs:
            req.eazyfi.session.remainingMs
        }
      });

    } catch (error) {
      logServerError(
        "dashboard-summary",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load dashboard."
      });
    }
  }
);
