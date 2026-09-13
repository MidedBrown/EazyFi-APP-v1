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

  const voucherCode =
    typeof body.voucher_code === "string"
      ? body.voucher_code.trim()
      : "";

  const packageId =
    typeof body.package_id === "string"
      ? body.package_id.trim()
      : "";

  if (!isNonEmptyString(voucherId) || !isUuid(voucherId)) {
    return sendError(res, 400, "A valid voucher_id is required.");
  }

  if (!isNonEmptyString(voucherCode)) {
    return sendError(res, 400, "Voucher code is required.");
  }

  if (!isNonEmptyString(packageId) || !isUuid(packageId)) {
    return sendError(res, 400, "A valid package_id is required.");
  }

  const supabase = createSupabase();

  try {
    const { data: existingVoucher, error: voucherError } =
      await supabase
        .from("vouchers")
        .select(
          "id, agent_id, package_id, voucher_code, status, used_at, created_at"
        )
        .eq("id", voucherId)
        .maybeSingle();

    if (voucherError) {
      throw voucherError;
    }

    if (!existingVoucher) {
      return sendError(res, 404, "Voucher not found.");
    }

    if (existingVoucher.status !== "available") {
      return sendError(
        res,
        409,
        "Used vouchers cannot be modified."
      );
    }

    const { data: packageData, error: packageError } =
      await supabase
        .from("packages")
        .select("id, agent_id, package_name, price_in_pesewas")
        .eq("id", packageId)
        .maybeSingle();

    if (packageError) {
      throw packageError;
    }

    if (!packageData) {
      return sendError(res, 404, "Package not found.");
    }

    if (packageData.agent_id !== existingVoucher.agent_id) {
      return sendError(
        res,
        400,
        "Voucher and package must belong to the same agent."
      );
    }

    const { data: duplicateVoucher, error: duplicateError } =
      await supabase
        .from("vouchers")
        .select("id")
        .eq("voucher_code", voucherCode)
        .neq("id", voucherId)
        .maybeSingle();

    if (duplicateError) {
      throw duplicateError;
    }

    if (duplicateVoucher) {
      return sendError(
        res,
        409,
        "This voucher code already exists."
      );
    }

    const { data: updatedVoucher, error: updateError } =
      await supabase
        .from("vouchers")
        .update({
          voucher_code: voucherCode,
          package_id: packageId
        })
        .eq("id", voucherId)
        .eq("status", "available")
        .select(
          "id, agent_id, package_id, voucher_code, status, used_at, created_at"
        )
        .single();

    if (updateError) {
      throw updateError;
    }

    return res.status(200).json({
      success: true,
      message: "Voucher updated successfully.",
      voucher: updatedVoucher
    });
  } catch (error) {
    console.error(
      "[EazyFi] Update-voucher error:",
      error?.message || error
    );

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
};
