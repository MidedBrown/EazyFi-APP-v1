const {
  requireAuthentication
} = require("../../lib/authenticate");

const {
  applySecurityHeaders,
  requireMethod
} = require("../../lib/security");


module.exports = requireAuthentication(
  async function handler(req, res) {

    applySecurityHeaders(res);

    if (!requireMethod(req, res, "GET")) {
      return;
    }

    /*
     * req.eazyfi was created by authenticate.js.
     *
     * The agent information here comes from our
     * trusted backend lookup, NOT from the browser.
     */
    const auth = req.eazyfi;

    return res.status(200).json({
      success: true,

      authenticated: true,

      agent: {
        agent_id:
          auth.agent.agent_id,

        agent_name:
          auth.agent.agent_name,

        phone:
          auth.agent.phone
      },

      session: {
        startedAt:
          auth.session.startedAt,

        expiresAt:
          auth.session.expiresAt,

        remainingMs:
          auth.session.remainingMs
      }
    });
  }
);
