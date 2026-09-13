const {
  getAdminSessionToken,
  getAdminSession,
  getAdminSessionRemainingSeconds
} = require("../../../lib/admin-auth");

const {
  sendError,
  requireMethod,
  applySecurityHeaders,
  logServerError
} = require("../../../lib/security");

module.exports = async (req, res) => {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "GET")) {
    return;
  }

  try {
    const token = getAdminSessionToken(req);
    const session = getAdminSession(token);

    if (!session) {
      return sendError(res, 401, "Admin session required.");
    }

    return res.status(200).json({
      success: true,
      admin: true,
      session: {
        expires_in: getAdminSessionRemainingSeconds(session)
      }
    });
  } catch (error) {
    logServerError("GET /api/admin/auth/me failed", error);
    return sendError(res, 500, "Unable to verify admin session.");
  }
};
