const {
  createSupabase
} = require("../../lib/supabase");

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
    let body = "";

    req.on("data", chunk => {
      body += chunk;

      if (
        Buffer.byteLength(body, "utf8") >
        20 * 1024
      ) {
        reject(
          new Error("Request body too large.")
        );

        req.destroy();
      }
    });

    req.on("end", () => {
      try {
        resolve(
          body
            ? JSON.parse(body)
            : {}
        );
      } catch {
        reject(
          new Error("Invalid JSON body.")
        );
      }
    });

    req.on("error", reject);
  });
}

function isAdminRequest(req) {
  const configuredKey =
    process.env.ADMIN_API_KEY;

  const suppliedKey =
    req.headers["x-admin-api-key"];

  if (
    !configuredKey ||
    typeof suppliedKey !== "string"
  ) {
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
    return sendError(
      res,
      403,
      "Admin authorization required."
    );
  }

  if (
    !isReasonableBodySize(
      req,
      20 * 1024
    )
  ) {
    return sendError(
      res,
      413,
      "Request body is too large."
    );
  }

  try {
    const body =
      await parseBody(req);

    const agentId =
      normalizeText(body.agent_id);

    const packageName =
      normalizeText(body.package_name);

    const priceInPesewas =
      Number(body.price_in_pesewas);

    if (
      !isNonEmptyString(agentId)
    ) {
      return sendError(
        res,
        400,
        "Agent ID is required."
      );
    }

    if (
      !isNonEmptyString(packageName)
    ) {
      return sendError(
        res,
        400,
        "Package name is required."
      );
    }

    if (
      packageName.length > 150
    ) {
      return sendError(
        res,
        400,
        "Package name is too long."
      );
    }

    if (
      !Number.isInteger(
        priceInPesewas
      ) ||
      priceInPesewas <= 0
    ) {
      return sendError(
        res,
        400,
        "price_in_pesewas must be a positive whole number."
      );
    }

    const supabase =
      createSupabase();

    /*
     * Verify that the target agent exists.
     */
    const {
      data: agent,
      error: agentError
    } = await supabase
      .from("agents")
      .select(
        "agent_id, agent_name"
      )
      .eq(
        "agent_id",
        agentId
      )
      .maybeSingle();

    if (agentError) {
      logServerError(
        "admin-create-package-agent-check",
        agentError
      );

      return sendError(
        res,
        500,
        "Unable to verify agent."
      );
    }

    if (!agent) {
      return sendError(
        res,
        404,
        "Agent was not found."
      );
    }

    /*
     * Prevent two identical packages for the
     * same agent.
     */
    const {
      data: existingPackage,
      error: existingError
    } = await supabase
      .from("packages")
      .select("id")
      .eq(
        "agent_id",
        agentId
      )
      .eq(
        "package_name",
        packageName
      )
      .eq(
        "price_in_pesewas",
        priceInPesewas
      )
      .maybeSingle();

    if (existingError) {
      logServerError(
        "admin-create-package-duplicate-check",
        existingError
      );

      return sendError(
        res,
        500,
        "Unable to check existing package."
      );
    }

    if (existingPackage) {
      return sendError(
        res,
        409,
        "That package already exists for this agent."
      );
    }

    const {
      data: packageData,
      error: packageError
    } = await supabase
      .from("packages")
      .insert({
        agent_id: agentId,
        package_name: packageName,
        price_in_pesewas:
          priceInPesewas
      })
      .select(
        "id, agent_id, package_name, price_in_pesewas, created_at"
      )
      .single();

    if (packageError) {
      logServerError(
        "admin-create-package",
        packageError
      );

      return sendError(
        res,
        500,
        "Unable to create package."
      );
    }

    return res.status(201).json({
      success: true,

      message:
        "Package created successfully.",

      package: packageData
    });

  } catch (error) {
    logServerError(
      "admin-create-package-handler",
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
      "Unable to create package."
    );
  }
};
