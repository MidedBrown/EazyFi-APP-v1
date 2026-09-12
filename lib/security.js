const crypto = require("crypto");


/*
 * Send a generic JSON error response.
 *
 * We avoid exposing internal database or authentication
 * details to the browser.
 */
function sendError(res, statusCode, message) {
  return res.status(statusCode).json({
    success: false,
    message
  });
}


/*
 * Only allow specific HTTP methods.
 */
function requireMethod(req, res, method) {
  if (req.method !== method) {
    res.setHeader("Allow", method);

    return sendError(
      res,
      405,
      "Method not allowed."
    );
  }

  return true;
}


/*
 * Prevent browsers and intermediaries from caching
 * sensitive API responses.
 */
function setNoStoreHeaders(res) {
  res.setHeader(
    "Cache-Control",
    "private, no-store, no-cache, must-revalidate"
  );

  res.setHeader(
    "Pragma",
    "no-cache"
  );

  res.setHeader(
    "Expires",
    "0"
  );
}


/*
 * Basic security headers for API responses.
 */
function setSecurityHeaders(res) {
  res.setHeader(
    "X-Content-Type-Options",
    "nosniff"
  );

  res.setHeader(
    "X-Frame-Options",
    "DENY"
  );

  res.setHeader(
    "Referrer-Policy",
    "no-referrer"
  );

  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  );
}


/*
 * Apply all standard EazyFi API security headers.
 */
function applySecurityHeaders(res) {
  setSecurityHeaders(res);
  setNoStoreHeaders(res);
}


/*
 * Safely compare two strings using a timing-safe comparison.
 *
 * Useful for:
 * - webhook signatures
 * - internal security tokens
 * - other sensitive comparisons
 */
function timingSafeEqualStrings(first, second) {
  if (
    typeof first !== "string" ||
    typeof second !== "string"
  ) {
    return false;
  }

  const firstBuffer = Buffer.from(first);
  const secondBuffer = Buffer.from(second);

  if (
    firstBuffer.length !==
    secondBuffer.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    firstBuffer,
    secondBuffer
  );
}


/*
 * Generate a cryptographically secure random value.
 *
 * We will use this later where a server-side random
 * identifier is required.
 */
function randomHex(bytes = 32) {
  return crypto
    .randomBytes(bytes)
    .toString("hex");
}


/*
 * Validate that a value is a non-empty string.
 */
function isNonEmptyString(value) {
  return (
    typeof value === "string" &&
    value.trim().length > 0
  );
}


/*
 * Normalize text safely.
 */
function normalizeText(value) {
  if (!isNonEmptyString(value)) {
    return "";
  }

  return value
    .trim()
    .replace(/\s+/g, " ");
}


/*
 * Normalize phone numbers without trying to guess
 * the customer's identity.
 */
function normalizePhone(value) {
  if (!isNonEmptyString(value)) {
    return "";
  }

  return value
    .trim()
    .replace(/[^\d+]/g, "");
}


/*
 * Check whether a value looks like a UUID.
 *
 * This is validation only.
 * Authorization is handled separately.
 */
function isUuid(value) {
  if (typeof value !== "string") {
    return false;
  }

  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value
  );
}


/*
 * Restrict an object to expected fields.
 *
 * This helps prevent clients from sending unexpected
 * fields such as:
 *
 * {
 *   agent_id: "ANOTHER_AGENT",
 *   wallet_balance: 999999
 * }
 *
 * API routes will explicitly choose which fields
 * are allowed instead of trusting the entire body.
 */
function pickAllowedFields(
  object,
  allowedFields
) {
  const result = {};

  if (
    !object ||
    typeof object !== "object" ||
    Array.isArray(object)
  ) {
    return result;
  }

  for (const field of allowedFields) {
    if (
      Object.prototype.hasOwnProperty.call(
        object,
        field
      )
    ) {
      result[field] = object[field];
    }
  }

  return result;
}


/*
 * Limit JSON request size at the application level.
 *
 * This is not a replacement for Vercel's request
 * limits; it is an additional application check.
 */
function isReasonableBodySize(req, maxBytes = 50 * 1024) {
  const contentLength =
    req.headers["content-length"];

  if (!contentLength) {
    return true;
  }

  const size = Number(contentLength);

  if (!Number.isFinite(size)) {
    return false;
  }

  return size <= maxBytes;
}


/*
 * Do not reveal internal errors to users.
 *
 * Detailed errors can be logged server-side,
 * while the client receives a generic message.
 */
function logServerError(context, error) {
  console.error(
    `[EazyFi:${context}]`,
    error?.message || error
  );
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
