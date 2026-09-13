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
  isReasonableBodySize,
  logServerError
} = require("../../../lib/security");

module.exports = async (req, res) => {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "POST")) {
    return;
  }

  if (!isReasonableBodySize(req.body, 5000)) {
    return sendError(res, 413, "Request body is too large.");
  }

  try {
    const expectedKey = process.env.ADMIN_API_KEY;

    if (!isNonEmptyString(expectedKey)) {
      return sendError(
        res,
        500,
        "Admin authentication is not configured."
      );
    }

    const body =
      typeof req.body === "object" && req.body !== null
        ? req.body
        : {};

    const suppliedKey =
      typeof body.admin_key === "string"
        ? body.admin_key.trim()
        : "";

    if (
      !suppliedKey ||
      !timingSafeEqualStrings(suppliedKey, expectedKey)
    ) {
      return sendError(res, 401, "Invalid admin credentials.");
    }

    const session = await createAdminSession();

    setAdminSessionCookie(res, session.token);

    return res.status(200).json({
      success: true,
      message: "Admin login successful.",
      session: {
        expires_at: session.expiresAt,
        expires_in: 30 * 60
      }
    });
  } catch (error) {
    logServerError(
      "POST /api/admin/auth/login failed",
      error
    );

    return sendError(
      res,
      500,
      "Unable to complete admin login."
    );
  }
};
