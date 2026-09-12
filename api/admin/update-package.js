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

  const packageName =
    typeof body.package_name === "string"
      ? body.package_name.trim()
      : "";

  const priceInPesewas = Number(body.price_in_pesewas);

  if (!isNonEmptyString(packageId) || !isUuid(packageId)) {
    return sendError(res, 400, "A valid package_id is required.");
  }

  if (!isNonEmptyString(packageName)) {
    return sendError(res, 400, "Package name is required.");
  }

  if (
    !Number.isInteger(priceInPesewas) ||
    priceInPesewas <= 0
  ) {
    return sendError(
      res,
      400,
      "price_in_pesewas must be a positive integer."
    );
  }

  const supabase = createSupabase();

  try {
    const { data: existingPackage, error: findError } =
      await supabase
        .from("packages")
        .select(
          "id, agent_id, package_name, price_in_pesewas, created_at"
        )
        .eq("id", packageId)
        .maybeSingle();

    if (findError) {
      throw findError;
    }

    if (!existingPackage) {
      return sendError(res, 404, "Package not found.");
    }

    const { data: duplicatePackage, error: duplicateError } =
      await supabase
        .from("packages")
        .select("id")
        .eq("agent_id", existingPackage.agent_id)
        .eq("package_name", packageName)
        .eq("price_in_pesewas", priceInPesewas)
        .neq("id", packageId)
        .maybeSingle();

    if (duplicateError) {
      throw duplicateError;
    }

    if (duplicatePackage) {
      return sendError(
        res,
        409,
        "This package already exists for the agent."
      );
    }

    const { data: updatedPackage, error: updateError } =
      await supabase
        .from("packages")
        .update({
          package_name: packageName,
          price_in_pesewas: priceInPesewas
        })
        .eq("id", packageId)
        .select(
          "id, agent_id, package_name, price_in_pesewas, created_at"
        )
        .single();

    if (updateError) {
      throw updateError;
    }

    return res.status(200).json({
      success: true,
      message: "Package updated successfully.",
      package: updatedPackage
    });
  } catch (error) {
    console.error(
      "[EazyFi] Update-package error:",
      error?.message || error
    );

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
};
