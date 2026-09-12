const { createSupabase } = require("../../lib/supabase");
const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  normalizeText,
  isNonEmptyString,
  isUuid,
  isReasonableBodySize,
  logServerError
} = require("../../lib/security");

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";

    req.on("data", (chunk) => {
      raw += chunk;

      if (Buffer.byteLength(raw, "utf8") > 20 * 1024) {
        reject(new Error("Request body too large."));
        req.destroy();
      }
    });

    req.on("end", () => {
      if (!raw) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error("Invalid JSON."));
      }
    });

    req.on("error", reject);
  });
}

function isAdminRequest(req) {
  const configuredKey = process.env.ADMIN_API_KEY;
  const suppliedKey = req.headers["x-admin-api-key"];

  if (!configuredKey || typeof suppliedKey !== "string") {
    return false;
  }

  return suppliedKey === configuredKey;
}

module.exports = async function handler(req, res) {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "POST")) {
    return;
  }

  if (!isAdminRequest(req)) {
    return sendError(res, 403, "Forbidden.");
  }

  if (!isReasonableBodySize(req, 20 * 1024)) {
    return sendError(res, 413, "Request body too large.");
  }

  try {
    const body = await parseBody(req);

    const packageId = normalizeText(body.package_id);
    const packageName = normalizeText(body.package_name);

    const rawPrice = body.price_in_pesewas;
    const priceInPesewas = Number(rawPrice);

    if (!isNonEmptyString(packageId) || !isUuid(packageId)) {
      return sendError(res, 400, "A valid package_id is required.");
    }

    if (!isNonEmptyString(packageName)) {
      return sendError(res, 400, "package_name is required.");
    }

    if (
      !Number.isSafeInteger(priceInPesewas) ||
      priceInPesewas <= 0
    ) {
      return sendError(
        res,
        400,
        "price_in_pesewas must be a positive whole number."
      );
    }

    const supabase = createSupabase();

    const { data: existingPackage, error: findError } = await supabase
      .from("packages")
      .select(`
        id,
        agent_id,
        package_name,
        price_in_pesewas,
        created_at
      `)
      .eq("id", packageId)
      .maybeSingle();

    if (findError) {
      logServerError("admin/update-package find", findError);
      return sendError(res, 500, "Unable to find package.");
    }

    if (!existingPackage) {
      return sendError(res, 404, "Package not found.");
    }

    const { data: duplicatePackage, error: duplicateError } = await supabase
      .from("packages")
      .select("id")
      .eq("agent_id", existingPackage.agent_id)
      .eq("package_name", packageName)
      .eq("price_in_pesewas", priceInPesewas)
      .neq("id", packageId)
      .maybeSingle();

    if (duplicateError) {
      logServerError(
        "admin/update-package duplicate",
        duplicateError
      );
      return sendError(res, 500, "Unable to validate package.");
    }

    if (duplicatePackage) {
      return sendError(
        res,
        409,
        "An identical package already exists for this agent."
      );
    }

    const { data: updatedPackage, error: updateError } = await supabase
      .from("packages")
      .update({
        package_name: packageName,
        price_in_pesewas: priceInPesewas
      })
      .eq("id", packageId)
      .select(`
        id,
        agent_id,
        package_name,
        price_in_pesewas,
        created_at
      `)
      .single();

    if (updateError) {
      logServerError(
        "admin/update-package update",
        updateError
      );
      return sendError(res, 500, "Unable to update package.");
    }

    return res.status(200).json({
      success: true,
      message: "Package updated successfully.",
      package: updatedPackage
    });
  } catch (error) {
    logServerError("admin/update-package", error);
    return sendError(res, 500, "Unable to update package.");
  }
};
