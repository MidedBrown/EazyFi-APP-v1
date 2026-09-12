const {
  requireAuthentication
} = require("../../lib/authenticate");

const {
  createSupabase
} = require("../../lib/supabase");

const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  logServerError,
  isUuid,
  normalizeText,
  isReasonableBodySize
} = require("../../lib/security");

const MAX_VOUCHERS_PER_REQUEST = 500;

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk;

      if (
        Buffer.byteLength(body, "utf8") >
        50 * 1024
      ) {
        reject(
          new Error("Request body too large.")
        );

        req.destroy();
      }
    });

    req.on("end", () => {
      try {
        if (!body) {
          resolve({});
          return;
        }

        resolve(JSON.parse(body));
      } catch {
        reject(
          new Error("Invalid JSON body.")
        );
      }
    });

    req.on("error", reject);
  });
}

function normalizeVoucherCodes(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  const cleaned = [];

  for (const item of value) {
    if (typeof item !== "string") {
      continue;
    }

    const code = item.trim();

    if (!code) {
      continue;
    }

    if (code.length > 200) {
      continue;
    }

    cleaned.push(code);
  }

  /*
   * Remove duplicate codes inside the same request.
   */
  return [
    ...new Set(cleaned)
  ];
}

module.exports = requireAuthentication(
  async function handler(req, res) {
    applySecurityHeaders(res);

    if (!requireMethod(req, res, "POST")) {
      return;
    }

    if (
      !isReasonableBodySize(
        req,
        50 * 1024
      )
    ) {
      return sendError(
        res,
        413,
        "Request body is too large."
      );
    }

    try {
      const body = await parseBody(req);

      if (
        !body ||
        typeof body !== "object" ||
        Array.isArray(body)
      ) {
        return sendError(
          res,
          400,
          "Invalid request body."
        );
      }

      /*
       * Only these two fields are accepted:
       *
       * package_id
       * voucher_codes
       *
       * agent_id is intentionally NOT accepted.
       */
      const packageId =
        normalizeText(body.package_id);

      const voucherCodes =
        normalizeVoucherCodes(
          body.voucher_codes
        );

      if (!isUuid(packageId)) {
        return sendError(
          res,
          400,
          "A valid package_id is required."
        );
      }

      if (voucherCodes.length === 0) {
        return sendError(
          res,
          400,
          "At least one voucher code is required."
        );
      }

      if (
        voucherCodes.length >
        MAX_VOUCHERS_PER_REQUEST
      ) {
        return sendError(
          res,
          400,
          `A maximum of ${MAX_VOUCHERS_PER_REQUEST} vouchers can be added at once.`
        );
      }

      const agentId =
        req.eazyfi.agent.agent_id;

      const supabase = createSupabase();

      /*
       * Verify that this package belongs to
       * the authenticated agent.
       */
      const {
        data: packageData,
        error: packageError
      } = await supabase
        .from("packages")
        .select(
          "id, agent_id, package_name, price_in_pesewas"
        )
        .eq("id", packageId)
        .eq("agent_id", agentId)
        .maybeSingle();

      if (packageError) {
        logServerError(
          "voucher-add-package-check",
          packageError
        );

        return sendError(
          res,
          500,
          "Unable to verify package."
        );
      }

      if (!packageData) {
        return sendError(
          res,
          403,
          "That package does not belong to your account."
        );
      }

      /*
       * Check which voucher codes already exist.
       *
       * This allows us to skip duplicates cleanly
       * instead of failing the entire batch.
       */
      const {
        data: existingVouchers,
        error: existingError
      } = await supabase
        .from("vouchers")
        .select("voucher_code")
        .in(
          "voucher_code",
          voucherCodes
        );

      if (existingError) {
        logServerError(
          "voucher-add-duplicate-check",
          existingError
        );

        return sendError(
          res,
          500,
          "Unable to check existing vouchers."
        );
      }

      const existingCodes = new Set(
        (existingVouchers || [])
          .map(row => row.voucher_code)
      );

      const newCodes =
        voucherCodes.filter(
          code =>
            !existingCodes.has(code)
        );

      if (newCodes.length === 0) {
        return res.status(200).json({
          success: true,
          message:
            "All submitted voucher codes already exist.",
          added: 0,
          skipped_duplicates:
            voucherCodes.length,
          failed: 0
        });
      }

      const rows = newCodes.map(
        voucherCode => ({
          agent_id: agentId,
          package_id: packageId,
          voucher_code: voucherCode,
          status: "available"
        })
      );

      /*
       * The composite foreign key in the database
       * guarantees that package_id and agent_id
       * belong together.
       */
      const {
        data: inserted,
        error: insertError
      } = await supabase
        .from("vouchers")
        .insert(rows)
        .select(
          "id, package_id, voucher_code, status, created_at"
        );

      if (insertError) {
        /*
         * A duplicate could theoretically appear
         * between the duplicate check and INSERT.
         *
         * The database UNIQUE constraint on
         * voucher_code remains the final protection.
         */
        if (
          insertError.code === "23505"
        ) {
          return sendError(
            res,
            409,
            "One or more voucher codes already exist. Please submit the remaining codes again."
          );
        }

        logServerError(
          "voucher-add-insert",
          insertError
        );

        return sendError(
          res,
          500,
          "Unable to add vouchers."
        );
      }

      return res.status(201).json({
        success: true,

        message:
          "Vouchers added successfully.",

        package: {
          id: packageData.id,
          package_name:
            packageData.package_name,
          price_in_pesewas:
            packageData.price_in_pesewas
        },

        added:
          inserted?.length || 0,

        skipped_duplicates:
          existingCodes.size,

        failed: 0
      });

    } catch (error) {
      logServerError(
        "voucher-add-handler",
        error
      );

      if (
        error.message ===
        "Invalid JSON body."
      ) {
        return sendError(
          res,
          400,
          "Invalid JSON request."
        );
      }

      if (
        error.message ===
        "Request body too large."
      ) {
        return sendError(
          res,
          413,
          "Request body is too large."
        );
      }

      return sendError(
        res,
        500,
        "Unable to add vouchers."
      );
    }
  }
);
