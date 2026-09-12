const crypto = require("node:crypto");

function sendError(res, statusCode, message) {
  return res.status(statusCode).json({
    success: false,
    error: message
  });
}

function requireMethod(req, res, allowedMethod) {
  if (req.method !== allowedMethod) {
    res.setHeader("Allow", allowedMethod);
    sendError(res, 405, "Method not allowed.");
    return false;
  }

  return true;
}

function setNoStoreHeaders(res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
}

function setSecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
}

function applySecurityHeaders(res) {
  setNoStoreHeaders(res);
  setSecurityHeaders(res);
}

function timingSafeEqualStrings(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  const aBuffer = Buffer.from(a, "utf8");
  const bBuffer = Buffer.from(b, "utf8");

  if (aBuffer.length !== bBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(aBuffer, bBuffer);
}

function randomHex(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function normalizeText(value) {
  if (!isNonEmptyString(value)) {
    return "";
  }

  return value.trim();
}

function normalizePhone(value) {
  if (!isNonEmptyString(value)) {
    return "";
  }

  return value.trim().replace(/[^\d+]/g, "");
}

function isUuid(value) {
  if (!isNonEmptyString(value)) {
    return false;
  }

  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value.trim()
  );
}

function pickAllowedFields(source, allowedFields) {
  const result = {};

  if (!source || typeof source !== "object") {
    return result;
  }

  for (const field of allowedFields) {
    if (Object.prototype.hasOwnProperty.call(source, field)) {
      result[field] = source[field];
    }
  }

  return result;
}

function isReasonableBodySize(body, maxBytes = 20000) {
  if (body === undefined || body === null) {
    return true;
  }

  if (typeof body === "string") {
    return Buffer.byteLength(body, "utf8") <= maxBytes;
  }

  try {
    return Buffer.byteLength(JSON.stringify(body), "utf8") <= maxBytes;
  } catch {
    return false;
  }
}

function logServerError(context, error) {
  console.error(`[EazyFi] ${context}:`, error?.message || error);
}

module.exports = {
  sendError,
  requireMethod,
  setNoStoreHeaders,
  setSecurityHeaders,
  applySecurityHeaders,
  timingSafeEqualStrings,
  randomHex,
  isNonEmptyString,
  normalizeText,
  normalizePhone,
  isUuid,
  pickAllowedFields,
  isReasonableBodySize,
  logServerError
};
