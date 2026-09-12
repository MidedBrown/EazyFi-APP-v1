const {
  createSupabase
} = require("../../lib/supabase");

const {
  applySecurityHeaders,
  requireMethod
} = require("../../lib/security");

const {
  authenticate
} = require("../../lib/authenticate");

function clearCookie(res, name) {
  res.setHeader(
    "Set-Cookie",
    [
      `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`
    ]
  );
}

module.exports = async function handler(req, res) {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "POST")) {
    return;
  }

  try {
    const auth = await authenticate(req);

    /*
     * If there is no valid EazyFi session,
     * simply clear the cookies and finish.
     */
    if (!auth.authenticated) {
      clearCookie(
        res,
        "eazyfi_access_token"
      );

      clearCookie(
        res,
        "eazyfi_refresh_token"
      );

      clearCookie(
        res,
        "eazyfi_session_started"
      );

      clearCookie(
        res,
        "eazyfi_session_signature"
      );

      return res.status(200).json({
        success: true,
        message: "Logged out."
      });
    }

    /*
     * Read the access token from the request cookie.
     * authenticate() has already validated it.
     */
    const cookieHeader =
      req.headers.cookie || "";

    const accessTokenMatch =
      cookieHeader.match(
        /(?:^|;\s*)eazyfi_access_token=([^;]+)/
      );

    const accessToken =
      accessTokenMatch
        ? decodeURIComponent(
            accessTokenMatch[1]
          )
        : null;

    /*
     * Revoke the current Supabase session.
     *
     * The logout endpoint uses the authenticated
     * user's access token, not the server secret key,
     * for the session revocation call.
     */
    if (accessToken) {
      const supabase = createSupabase();

      const {
        error
      } = await supabase.auth.admin.signOut(
        accessToken,
        "local"
      );

      if (error) {
        console.warn(
          "EazyFi Supabase logout warning:",
          error.message
        );
      }
    }

    /*
     * Remove all EazyFi authentication cookies.
     */
    clearCookie(
      res,
      "eazyfi_access_token"
    );

    clearCookie(
      res,
      "eazyfi_refresh_token"
    );

    clearCookie(
      res,
      "eazyfi_session_started"
    );

    clearCookie(
      res,
      "eazyfi_session_signature"
    );

    return res.status(200).json({
      success: true,
      message: "Logged out successfully."
    });

  } catch (error) {
    console.error(
      "EazyFi logout error:",
      error.message
    );

    /*
     * Even if server-side revocation fails,
     * remove the browser session cookies.
     */
    clearCookie(
      res,
      "eazyfi_access_token"
    );

    clearCookie(
      res,
      "eazyfi_refresh_token"
    );

    clearCookie(
      res,
      "eazyfi_session_started"
    );

    clearCookie(
      res,
      "eazyfi_session_signature"
    );

    return res.status(200).json({
      success: true,
      message: "Logged out."
    });
  }
};
