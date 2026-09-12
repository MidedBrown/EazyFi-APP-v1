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
      /*
       * IMPORTANT:
       * Never take agent_id from req.query.
       *
       * The authenticated session determines which
       * agent is allowed to see the packages.
       */
      const agentId =
        req.eazyfi.agent.agent_id;

      const supabase = createSupabase();

      const {
        data: packages,
        error
      } = await supabase
        .from("packages")
        .select(
          "id, package_name, price_in_pesewas, created_at"
        )
        .eq("agent_id", agentId)
        .order("price_in_pesewas", {
          ascending: true
        });

      if (error) {
        logServerError(
          "packages-list",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Unable to load packages."
        });
      }

      return res.status(200).json({
        success: true,
        packages: packages || []
      });

    } catch (error) {
      logServerError(
        "packages-list-handler",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load packages."
      });
    }
  }
);
