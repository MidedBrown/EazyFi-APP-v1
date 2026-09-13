const {
  createAdminSession,
  setAdminSessionCookie
} = require("../../../lib/admin-auth");

const {
  sendError,
  requireMethod,
  applySecurityHeaders,
  isNonEmptyString,
  timingSafeEqualStrings,
  logServerError
} = require("../../../lib/security");

module.exports = async (req, res) => {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "POST")) {
    return;
  }

  try {
    const expectedKey = process.env.ADMIN_API_KEY;

    if (!isNonEmptyString(expectedKey)) {
      return sendError(res, 500, "Admin authentication is not configured.");
    }

    const body =
      typeof req.body === "object" && req.body !== null
        ? req.body
        : {};

    const suppliedKey =
      typeof body.admin_key === "string"
        ? body.admin_key.trim()
        : "";

    if (!suppliedKey || !timingSafeEqualStrings(suppliedKey, expectedKey)) {
      return sendError(res, 401, "Invalid admin credentials.");
    }

    const sessionToken = createAdminSession();

    setAdminSessionCookie(res, sessionToken);

    return res.status(200).json({
      success: true,
      message: "Admin login successful.",
      session: {
        expires_in: 30 * 60
      }
    });
  } catch (error) {
    logServerError("POST /api/admin/auth/login failed", error);
    return sendError(res, 500, "Unable to complete admin login.");
  }
};
