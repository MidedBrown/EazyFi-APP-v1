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

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

module.exports = requireAuthentication(
  async function handler(req, res) {
    applySecurityHeaders(res);

    if (!requireMethod(req, res, "GET")) {
      return;
    }

    try {
      /*
       * The authenticated session determines the agent.
       *
       * We intentionally do NOT accept agent_id
       * from the query string.
       */
      const agentId =
        req.eazyfi.agent.agent_id;

      /*
       * Optional pagination limit.
       *
       * Example:
       * /api/sales/list?limit=50
       */
      const requestedLimit =
        Number(req.query?.limit);

      let limit = DEFAULT_LIMIT;

      if (
        Number.isInteger(requestedLimit) &&
        requestedLimit > 0
      ) {
        limit = Math.min(
          requestedLimit,
          MAX_LIMIT
        );
      }

      const supabase = createSupabase();

      const {
        data: transactions,
        error
      } = await supabase
        .from("transactions")
        .select(`
          id,
          paystack_ref,
          package_id,
          customer_phone,
          amount_paid,
          voucher_code,
          sms_status,
          status,
          created_at,
          packages (
            package_name,
            price_in_pesewas
          )
        `)
        .eq("agent_id", agentId)
        .order("created_at", {
          ascending: false
        })
        .limit(limit);

      if (error) {
        logServerError(
          "sales-list",
          error
        );

        return sendError(
          res,
          500,
          "Unable to load sales."
        );
      }

      /*
       * Return only the information needed
       * by the portal.
       */
      const sales = (
        transactions || []
      ).map(transaction => ({
        id: transaction.id,

        reference:
          transaction.paystack_ref,

        customer_phone:
          transaction.customer_phone,

        amount_paid:
          transaction.amount_paid,

        voucher_code:
          transaction.voucher_code,

        sms_status:
          transaction.sms_status,

        status:
          transaction.status,

        created_at:
          transaction.created_at,

        package:
          transaction.packages
            ? {
                package_name:
                  transaction.packages
                    .package_name,

                price_in_pesewas:
                  transaction.packages
                    .price_in_pesewas
              }
            : null
      }));

      return res.status(200).json({
        success: true,

        sales,

        count: sales.length,

        limit
      });

    } catch (error) {
      logServerError(
        "sales-list-handler",
        error
      );

      return sendError(
        res,
        500,
        "Unable to load sales."
      );
    }
  }
);
