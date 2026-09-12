const {
  authenticate
} = require("../../lib/authenticate");

const {
  applySecurityHeaders,
  requireMethod
} = require("../../lib/security");

module.exports = async function handler(req, res) {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "GET")) {
    return;
  }

  const auth = await authenticate(req);

  if (!auth.authenticated) {
    return res.status(401).json({
      success: false,
      authenticated: false,
      reason: auth.reason
    });
  }

  return res.status(200).json({
    success: true,
    authenticated: true,

    agent: {
      agent_id:
        auth.agent.agent_id,

      agent_name:
        auth.agent.agent_name
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
};
