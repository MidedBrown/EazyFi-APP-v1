const {
  getAdminSessionToken,
  destroyAdminSession,
  clearAdminSessionCookie
} = require("../../../lib/admin-auth");

const {
  sendError,
  requireMethod,
  applySecurityHeaders,
  logServerError
} = require("../../../lib/security");

module.exports = async (req, res) => {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "POST")) {
    return;
  }

  try {
    const token = getAdminSessionToken(req);

    if (token) {
      await destroyAdminSession(token);
    }

    clearAdminSessionCookie(res);

    return res.status(200).json({
      success: true,
      message: "Admin logout successful."
    });
  } catch (error) {
    logServerError(
      "POST /api/admin/auth/logout failed",
      error
    );

    return sendError(
      res,
      500,
      "Unable to complete admin logout."
    );
  }
};
