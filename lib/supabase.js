const { createClient } = require("@supabase/supabase-js");

/*
 * EazyFi Supabase configuration
 *
 * IMPORTANT:
 * This file is SERVER-SIDE ONLY.
 *
 * Never import this file from public/index.html
 * or any JavaScript that runs in the browser.
 */

function getSupabaseUrl() {
  const url = process.env.SUPABASE_URL;

  if (!url) {
    throw new Error("SUPABASE_URL is not configured.");
  }

  return url;
}


/*
 * Supabase Auth client
 *
 * Uses the publishable key.
 *
 * This client is used for operations such as:
 * - signing users in
 * - validating Supabase Auth sessions
 *
 * Sessions are NOT persisted by this server-side client.
 */

function createAuthSupabase() {
  const url = getSupabaseUrl();

  const key = process.env.SUPABASE_PUBLISHABLE_KEY;

  if (!key) {
    throw new Error(
      "SUPABASE_PUBLISHABLE_KEY is not configured."
    );
  }

  return createClient(url, key, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false
    }
  });
}


/*
 * EazyFi trusted backend client
 *
 * Uses the Supabase Secret Key.
 *
 * This client has elevated database access and bypasses RLS.
 *
 * Therefore:
 * - NEVER send this key to the browser.
 * - NEVER put it in public/index.html.
 * - NEVER log the key.
 * - NEVER put it in GitHub.
 *
 * Every API endpoint using this client must perform
 * its own authorization checks before accessing data.
 */

function createSupabase() {
  const url = getSupabaseUrl();

  const secretKey = process.env.SUPABASE_SECRET_KEY;

  if (!secretKey) {
    throw new Error(
      "SUPABASE_SECRET_KEY is not configured."
    );
  }

  return createClient(url, secretKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false
    }
  });
}


module.exports = {
  createAuthSupabase,
  createSupabase
};
