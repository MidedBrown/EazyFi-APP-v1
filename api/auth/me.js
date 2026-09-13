const { requireAuthentication } = require("../../lib/authenticate");
const {
  sendError,
  requireMethod,
  applySecurityHeaders,
  logServerError
} = require("../../lib/security");

module.exports = requireAuthentication(async (req, res, auth) => {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "GET")) {
    return;
  }

  try {
    return res.status(200).json({
      success: true,
      user: {
        id: auth.user.id,
        email: auth.user.email || null
      },
      agent: {
        id: auth.agent.id,
        agent_id: auth.agent.agent_id,
        agent_name: auth.agent.agent_name,
        phone: auth.agent.phone,
        terminal_id: auth.agent.terminal_id,
        wallet_balance: auth.agent.wallet_balance,
        account_locked: auth.agent.account_locked
      },
      session: {
        started_at: auth.session.startedAt,
        expires_at: auth.session.expiresAt,
        remaining_seconds: auth.session.remainingSeconds
      }
    });
  } catch (error) {
    logServerError("GET /api/auth/me failed", error);
    return sendError(res, 500, "Unable to load account information.");
  }
});
