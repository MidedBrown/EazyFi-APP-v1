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

  const packageId =
    typeof body.package_id === "string"
      ? body.package_id.trim()
      : "";

  if (!isNonEmptyString(packageId) || !isUuid(packageId)) {
    return sendError(res, 400, "A valid package_id is required.");
  }

  const supabase = createSupabase();

  try {
    const { data: packageData, error: packageError } =
      await supabase
        .from("packages")
        .select(
          "id, agent_id, package_name, price_in_pesewas"
        )
        .eq("id", packageId)
        .maybeSingle();

    if (packageError) {
      throw packageError;
    }

    if (!packageData) {
      return sendError(res, 404, "Package not found.");
    }

    const { count: voucherCount, error: voucherCountError } =
      await supabase
        .from("vouchers")
        .select("id", {
          count: "exact",
          head: true
        })
        .eq("package_id", packageId);

    if (voucherCountError) {
      throw voucherCountError;
    }

    if ((voucherCount || 0) > 0) {
      return sendError(
        res,
        409,
        "Cannot delete a package that has vouchers assigned to it."
      );
    }

    const { error: deleteError } = await supabase
      .from("packages")
      .delete()
      .eq("id", packageId);

    if (deleteError) {
      throw deleteError;
    }

    return res.status(200).json({
      success: true,
      message: "Package deleted successfully.",
      package: packageData
    });
  } catch (error) {
    console.error(
      "[EazyFi] Delete-package error:",
      error?.message || error
    );

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
};
