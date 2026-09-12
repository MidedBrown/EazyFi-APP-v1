const { createSupabase } = require("../../lib/supabase");
const {
  applySecurityHeaders,
  requireMethod,
  sendError,
  timingSafeEqualStrings
} = require("../../lib/security");

module.exports = async function handler(req, res) {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "GET")) return;

  const configuredAdminKey = process.env.ADMIN_API_KEY || "";
  const suppliedAdminKey = req.headers["x-admin-api-key"] || "";

  if (
    !configuredAdminKey ||
    !timingSafeEqualStrings(suppliedAdminKey, configuredAdminKey)
  ) {
    return sendError(res, 401, "Unauthorized.");
  }

  const supabase = createSupabase();

  try {
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
      throw error;
    }

    const formattedPackages = (packages || []).map((pkg) => ({
      id: pkg.id,
      agent_id: pkg.agent_id,
      agent_name: pkg.agents?.agent_name || null,
      package_name: pkg.package_name,
      price_in_pesewas: pkg.price_in_pesewas,
      created_at: pkg.created_at
    }));

    return res.status(200).json({
      success: true,
      packages: formattedPackages
    });
  } catch (error) {
    console.error(
      "[EazyFi] List-packages error:",
      error?.message || error
    );

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
};
