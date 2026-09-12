const { createSupabase } = require("../../lib/supabase");
const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  logServerError
} = require("../../lib/security");

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

  if (!requireMethod(req, res, "GET")) {
    return;
  }

  if (!isAdminRequest(req)) {
    return sendError(res, 403, "Forbidden.");
  }

  try {
    const supabase = createSupabase();

    const { data: packages, error } = await supabase
      .from("packages")
      .select(`
        id,
        agent_id,
        package_name,
        price_in_pesewas,
        created_at,
        agents (
          agent_name
        )
      `)
      .order("created_at", { ascending: false });

    if (error) {
      logServerError("admin/list-packages", error);
      return sendError(res, 500, "Unable to load packages.");
    }

    const formattedPackages = packages.map((item) => ({
      id: item.id,
      agent_id: item.agent_id,
      agent_name: item.agents?.agent_name || null,
      package_name: item.package_name,
      price_in_pesewas: item.price_in_pesewas,
      created_at: item.created_at
    }));

    return res.status(200).json({
      success: true,
      count: formattedPackages.length,
      packages: formattedPackages
    });
  } catch (error) {
    logServerError("admin/list-packages", error);
    return sendError(res, 500, "Unable to load packages.");
  }
};
