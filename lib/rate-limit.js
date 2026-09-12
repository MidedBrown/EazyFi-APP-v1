/*
 * EazyFi in-memory rate limiter
 *
 * This is a fast first-line protection layer.
 *
 * IMPORTANT:
 * Vercel Functions can run on different instances, so this
 * memory is NOT a global security boundary.
 *
 * Persistent account locking is handled separately in Supabase.
 */

const buckets = new Map();


/*
 * Remove expired entries periodically so the Map does not
 * grow forever inside a warm function instance.
 */
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;

let lastCleanup = Date.now();


function cleanupExpiredEntries(now) {
  if (now - lastCleanup < CLEANUP_INTERVAL_MS) {
    return;
  }

  for (const [key, bucket] of buckets.entries()) {
    if (bucket.resetAt <= now) {
      buckets.delete(key);
    }
  }

  lastCleanup = now;
}


/*
 * Check whether an identifier is allowed to make another request.
 *
 * Example:
 *
 * checkRateLimit("ip:123.123.123.123")
 *
 * Returns:
 *
 * {
 *   allowed: true,
 *   remaining: 4,
 *   retryAfterSeconds: 0
 * }
 */
function checkRateLimit(
  identifier,
  options = {}
) {
  const limit = Number(options.limit || 5);

  const windowMs = Number(
    options.windowMs || 60 * 1000
  );

  const now = Date.now();

  cleanupExpiredEntries(now);

  if (!identifier) {
    return {
      allowed: false,
      remaining: 0,
      retryAfterSeconds: Math.ceil(
        windowMs / 1000
      )
    };
  }

  let bucket = buckets.get(identifier);

  /*
   * Start a new window.
   */
  if (!bucket || bucket.resetAt <= now) {
    bucket = {
      count: 0,
      resetAt: now + windowMs
    };

    buckets.set(identifier, bucket);
  }

  /*
   * Limit reached.
   */
  if (bucket.count >= limit) {
    const retryAfterMs =
      bucket.resetAt - now;

    return {
      allowed: false,
      remaining: 0,
      retryAfterSeconds: Math.max(
        1,
        Math.ceil(
          retryAfterMs / 1000
        )
      )
    };
  }

  /*
   * Count this request.
   */
  bucket.count += 1;

  return {
    allowed: true,
    remaining: Math.max(
      0,
      limit - bucket.count
    ),
    retryAfterSeconds: 0
  };
}


/*
 * Get the client IP address.
 *
 * Vercel commonly provides x-forwarded-for.
 *
 * We take the first address in the list.
 */
function getClientIp(req) {
  const forwarded =
    req.headers["x-forwarded-for"];

  if (forwarded) {
    return forwarded
      .split(",")[0]
      .trim();
  }

  return (
    req.headers["x-real-ip"] ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}


/*
 * Convenience function specifically for login.
 *
 * We intentionally keep this separate from the generic
 * limiter so different API endpoints can have different
 * limits later.
 */
function checkLoginRateLimit(req) {
  const ip = getClientIp(req);

  return {
    ip,

    ...checkRateLimit(
      `login-ip:${ip}`,
      {
        limit: 5,
        windowMs: 60 * 1000
      }
    )
  };
}


module.exports = {
  checkRateLimit,
  checkLoginRateLimit,
  getClientIp
};
