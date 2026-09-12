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

    const voucherId = normalizeText(body.voucher_id);

    if (!isNonEmptyString(voucherId) || !isUuid(voucherId)) {
      return sendError(res, 400, "A valid voucher_id is required.");
    }

    const supabase = createSupabase();

    const { data: voucher, error: findError } = await supabase
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
      logServerError("admin/delete-voucher find", findError);
      return sendError(res, 500, "Unable to find voucher.");
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
      logServerError("admin/delete-voucher delete", deleteError);
      return sendError(res, 500, "Unable to delete voucher.");
    }

    return res.status(200).json({
      success: true,
      message: "Voucher deleted successfully.",
      voucher: {
        id: voucher.id,
        agent_id: voucher.agent_id,
        package_id: voucher.package_id,
        voucher_code: voucher.voucher_code
      }
    });
  } catch (error) {
    logServerError("admin/delete-voucher", error);
    return sendError(res, 500, "Unable to delete voucher.");
  }
};
