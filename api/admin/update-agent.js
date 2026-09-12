const { createSupabase } = require("../../lib/supabase");
const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  normalizeText,
  isNonEmptyString,
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

    const agentId = normalizeText(body.agent_id);
    const agentName = normalizeText(body.agent_name);
    const phone = normalizeText(body.phone);
    const terminalId = normalizeText(body.terminal_id);

    if (!isNonEmptyString(agentId)) {
      return sendError(res, 400, "agent_id is required.");
    }

    if (!isNonEmptyString(agentName)) {
      return sendError(res, 400, "agent_name is required.");
    }

    const supabase = createSupabase();

    const { data: existingAgent, error: findError } = await supabase
      .from("agents")
      .select(`
        id,
        agent_id,
        agent_name,
        phone,
        terminal_id
      `)
      .eq("agent_id", agentId)
      .maybeSingle();

    if (findError) {
      logServerError("admin/update-agent find", findError);
      return sendError(res, 500, "Unable to find agent.");
    }

    if (!existingAgent) {
      return sendError(res, 404, "Agent not found.");
    }

    if (terminalId) {
      const { data: terminalOwner, error: terminalError } = await supabase
        .from("agents")
        .select("id, agent_id")
        .eq("terminal_id", terminalId)
        .neq("id", existingAgent.id)
        .maybeSingle();

      if (terminalError) {
        logServerError(
          "admin/update-agent terminal check",
          terminalError
        );
        return sendError(res, 500, "Unable to validate terminal ID.");
      }

      if (terminalOwner) {
        return sendError(
          res,
          409,
          "That terminal ID is already assigned to another agent."
        );
      }
    }

    const { data: updatedAgent, error: updateError } = await supabase
      .from("agents")
      .update({
        agent_name: agentName,
        phone: phone || null,
        terminal_id: terminalId || null
      })
      .eq("id", existingAgent.id)
      .select(`
        agent_id,
        agent_name,
        phone,
        terminal_id
      `)
      .single();

    if (updateError) {
      logServerError("admin/update-agent update", updateError);
      return sendError(res, 500, "Unable to update agent.");
    }

    return res.status(200).json({
      success: true,
      message: "Agent updated successfully.",
      agent: updatedAgent
    });
  } catch (error) {
    logServerError("admin/update-agent", error);
    return sendError(res, 500, "Unable to update agent.");
  }
};
