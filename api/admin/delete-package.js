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

    if (!isNonEmptyString(packageId) || !isUuid(packageId)) {
      return sendError(res, 400, "A valid package_id is required.");
    }

    const supabase = createSupabase();

    const { data: existingPackage, error: findError } = await supabase
      .from("packages")
      .select(`
        id,
        agent_id,
        package_name,
        price_in_pesewas
      `)
      .eq("id", packageId)
      .maybeSingle();

    if (findError) {
      logServerError("admin/delete-package find", findError);
      return sendError(res, 500, "Unable to find package.");
    }

    if (!existingPackage) {
      return sendError(res, 404, "Package not found.");
    }

    const { count: voucherCount, error: voucherCountError } = await supabase
      .from("vouchers")
      .select("id", { count: "exact", head: true })
      .eq("package_id", packageId);

    if (voucherCountError) {
      logServerError(
        "admin/delete-package voucher count",
        voucherCountError
      );
      return sendError(res, 500, "Unable to check package vouchers.");
    }

    if ((voucherCount || 0) > 0) {
      return sendError(
        res,
        409,
        "Package cannot be deleted while vouchers are assigned to it."
      );
    }

    const { error: deleteError } = await supabase
      .from("packages")
      .delete()
      .eq("id", packageId);

    if (deleteError) {
      logServerError("admin/delete-package delete", deleteError);
      return sendError(res, 500, "Unable to delete package.");
    }

    return res.status(200).json({
      success: true,
      message: "Package deleted successfully.",
      package: existingPackage
    });
  } catch (error) {
    logServerError("admin/delete-package", error);
    return sendError(res, 500, "Unable to delete package.");
  }
};
