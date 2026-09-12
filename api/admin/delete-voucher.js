const { createSupabase } = require("../../lib/supabase");
const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  isNonEmptyString,
  isReasonableBodySize,
  isUuid,
  timingSafeEqualStrings
} = require("../../lib/security");

function parseBody(req) {
  if (req.body && typeof req.body === "object") {
    return req.body;
  }

  if (typeof req.body === "string") {
    try {
      return JSON.parse(req.body);
    } catch {
      return null;
    }
  }

  return null;
}

module.exports = async function handler(req, res) {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "POST")) return;

  const configuredAdminKey = process.env.ADMIN_API_KEY || "";
  const suppliedAdminKey = req.headers["x-admin-api-key"] || "";

  if (
    !configuredAdminKey ||
    !timingSafeEqualStrings(suppliedAdminKey, configuredAdminKey)
  ) {
    return sendError(res, 401, "Unauthorized.");
  }

  if (!isReasonableBodySize(req.body, 20000)) {
    return sendError(res, 413, "Request body is too large.");
  }

  const body = parseBody(req);

  if (!body) {
    return sendError(res, 400, "Invalid JSON body.");
  }

  const voucherId =
    typeof body.voucher_id === "string"
      ? body.voucher_id.trim()
      : "";

  if (!isNonEmptyString(voucherId) || !isUuid(voucherId)) {
    return sendError(res, 400, "A valid voucher_id is required.");
  }

  const supabase = createSupabase();

  try {
    const { data: voucher, error: findError } =
      await supabase
        .from("vouchers")
        .select(`
          id,
          agent_id,
          package_id,
          voucher_code,
          status,
          used_at,
          created_at
        `)
        .eq("id", voucherId)
        .maybeSingle();

    if (findError) {
      throw findError;
    }

    if (!voucher) {
      return sendError(res, 404, "Voucher not found.");
    }

    if (voucher.status !== "available") {
      return sendError(
        res,
        409,
        "Used vouchers cannot be deleted."
      );
    }

    const { error: deleteError } = await supabase
      .from("vouchers")
      .delete()
      .eq("id", voucherId)
      .eq("status", "available");

    if (deleteError) {
      throw deleteError;
    }

    return res.status(200).json({
      success: true,
      message: "Voucher deleted successfully.",
      voucher
    });
  } catch (error) {
    console.error(
      "[EazyFi] Delete-voucher error:",
      error?.message || error
    );

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
};
