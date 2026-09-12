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

    if (!isNonEmptyString(agentId)) {
      return sendError(res, 400, "agent_id is required.");
    }

    const supabase = createSupabase();

    const { data: agent, error: findError } = await supabase
      .from("agents")
      .select(`
        id,
        agent_id,
        agent_name,
        account_locked,
        login_failed_attempts
      `)
      .eq("agent_id", agentId)
      .maybeSingle();

    if (findError) {
      logServerError("admin/unlock-agent find", findError);
      return sendError(res, 500, "Unable to find agent.");
    }

    if (!agent) {
      return sendError(res, 404, "Agent not found.");
    }

    const { data: updatedAgent, error: updateError } = await supabase
      .from("agents")
      .update({
        account_locked: false,
        login_failed_attempts: 0,
        account_locked_at: null,
        account_locked_reason: null
      })
      .eq("id", agent.id)
      .select(`
        agent_id,
        agent_name,
        account_locked,
        login_failed_attempts,
        account_locked_at,
        account_locked_reason
      `)
      .single();

    if (updateError) {
      logServerError("admin/unlock-agent update", updateError);
      return sendError(res, 500, "Unable to unlock agent.");
    }

    return res.status(200).json({
      success: true,
      message: "Agent account unlocked successfully.",
      agent: updatedAgent
    });
  } catch (error) {
    logServerError("admin/unlock-agent", error);
    return sendError(res, 500, "Unable to unlock agent.");
  }
};
