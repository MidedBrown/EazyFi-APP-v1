const { createSupabase } = require("../../lib/supabase");
const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  isNonEmptyString,
  isReasonableBodySize,
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

  const agentId =
    typeof body.agent_id === "string"
      ? body.agent_id.trim()
      : "";

  const packageName =
    typeof body.package_name === "string"
      ? body.package_name.trim()
      : "";

  const priceInPesewas = Number(body.price_in_pesewas);

  if (!isNonEmptyString(agentId)) {
    return sendError(res, 400, "Agent ID is required.");
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
    const { data: agent, error: agentError } = await supabase
      .from("agents")
      .select("agent_id")
      .eq("agent_id", agentId)
      .maybeSingle();

    if (agentError) {
      throw agentError;
    }

    if (!agent) {
      return sendError(res, 404, "Agent not found.");
    }

    const { data: existingPackage, error: duplicateError } =
      await supabase
        .from("packages")
        .select("id")
        .eq("agent_id", agentId)
        .eq("package_name", packageName)
        .eq("price_in_pesewas", priceInPesewas)
        .maybeSingle();

    if (duplicateError) {
      throw duplicateError;
    }

    if (existingPackage) {
      return sendError(
        res,
        409,
        "This package already exists for the agent."
      );
    }

    const { data: packageData, error: packageError } =
      await supabase
        .from("packages")
        .insert({
          agent_id: agentId,
          package_name: packageName,
          price_in_pesewas: priceInPesewas
        })
        .select(
          "id, agent_id, package_name, price_in_pesewas, created_at"
        )
        .single();

    if (packageError) {
      throw packageError;
    }

    return res.status(201).json({
      success: true,
      message: "Package created successfully.",
      package: packageData
    });
  } catch (error) {
    console.error(
      "[EazyFi] Create-package error:",
      error?.message || error
    );

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
};
