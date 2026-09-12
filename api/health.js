const {
  applySecurityHeaders,
  requireMethod
} = require("../lib/security");

module.exports = function handler(req, res) {
  applySecurityHeaders(res);

  if (!requireMethod(req, res, "GET")) {
    return;
  }

  return res.status(200).json({
    success: true,
    status: "online",
    service: "EazyFi Agent Portal API",
    timestamp: new Date().toISOString()
  });
};
