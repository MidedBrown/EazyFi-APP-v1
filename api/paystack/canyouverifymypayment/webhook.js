const crypto = require("crypto");

const {
  createSupabase
} = require("../../../lib/supabase");

const {
  applySecurityHeaders,
  timingSafeEqualStrings,
  logServerError
} = require("../../../lib/security");

const WEBHOOK_SECRET =
  process.env.PAYSTACK_SECRET_KEY;

const MNOTIFY_API_KEY =
  process.env.MNOTIFY_API_KEY;

const MNOTIFY_ENDPOINT =
  "https://api.mnotify.com/api/sms/quick";

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk;

      if (
        Buffer.byteLength(body, "utf8") >
        256 * 1024
      ) {
        reject(
          new Error("Webhook body too large.")
        );

        req.destroy();
      }
    });

    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function verifyPaystackSignature(
  rawBody,
  signature
) {
  if (
    !WEBHOOK_SECRET ||
    !signature
  ) {
    return false;
  }

  const expected =
    crypto
      .createHmac(
        "sha512",
        WEBHOOK_SECRET
      )
      .update(rawBody)
      .digest("hex");

  return timingSafeEqualStrings(
    expected,
    signature
  );
}

function firstValue(...values) {
  for (const value of values) {
    if (
      value !== undefined &&
      value !== null &&
      String(value).trim() !== ""
    ) {
      return value;
    }
  }

  return null;
}

function normalizePhone(value) {
  if (!value) {
    return null;
  }

  return String(value)
    .trim()
    .replace(/[^\d+]/g, "");
}

function getAgentIdentifier(data) {
  const metadata =
    data?.metadata || {};

  return firstValue(
    metadata.agent_id,
    metadata.agentId,
    metadata.agent,
    data?.agent_id
  );
}

function getTerminalIdentifier(data) {
  const metadata =
    data?.metadata || {};

  const virtualTerminal =
    metadata.virtual_terminal || {};

  return firstValue(
    metadata.virtual_terminal_code,
    metadata.terminal_id,
    metadata.terminalId,
    metadata.virtual_terminal_id,
    metadata.virtualTerminalId,
    metadata.terminal?.id,
    metadata.virtual_terminal?.id,
    metadata.virtual_terminal?.code,
    data?.terminal_id,
    data?.terminal_code,
    data?.device_id,
    data?.pos_device_id,
    data?.pos_id,
    data?.authorization?.terminal_code,
    data?.source?.identifier,
    virtualTerminal.code
  );
}

function getPackageId(data) {
  const metadata =
    data?.metadata || {};

  return firstValue(
    metadata.package_id,
    metadata.packageId,
    data?.package_id,
    data?.packageId
  );
}

function getCustomerPhone(data) {
  const metadata =
    data?.metadata || {};

  const customFields =
    metadata.custom_fields || {};

  return normalizePhone(
    firstValue(
      metadata.recipient_phone,
      metadata.recipientPhone,
      metadata.recipient,
      metadata.phone,
      metadata.customer_phone,
      customFields.recipient_phone,
      customFields.recipientPhone,
      customFields.phone,
      data?.customer?.phone,
      data?.customer?.international_format_phone,
      data?.phone
    )
  );
}

async function findAgent(
  supabase,
  agentIdentifier,
  terminalIdentifier
) {
  if (agentIdentifier) {
    const {
      data: agent,
      error
    } = await supabase
      .from("agents")
      .select(
        "id, agent_id, agent_name, phone, terminal_id"
      )
      .eq(
        "agent_id",
        String(agentIdentifier)
      )
      .maybeSingle();

    if (error) {
      throw error;
    }

    if (agent) {
      return agent;
    }
  }

  if (terminalIdentifier) {
    const {
      data: agent,
      error
    } = await supabase
      .from("agents")
      .select(
        "id, agent_id, agent_name, phone, terminal_id"
      )
      .eq(
        "terminal_id",
        String(terminalIdentifier)
      )
      .maybeSingle();

    if (error) {
      throw error;
    }

    if (agent) {
      return agent;
    }
  }

  return null;
}

async function sendVoucherSms({
  recipient,
  voucherCode,
  packageName,
  reference
}) {
  if (!MNOTIFY_API_KEY) {
    throw new Error(
      "MNOTIFY_API_KEY is not configured."
    );
  }

  if (!recipient) {
    throw new Error(
      "Customer phone number is missing."
    );
  }

  const sender =
    process.env.MNOTIFY_SENDER_ID ||
    "EazyFi";

  const message =
    `EazyFi payment successful. ` +
    `Package: ${packageName}. ` +
    `Voucher: ${voucherCode}. ` +
    `Ref: ${reference}`;

  const response =
    await fetch(
      `${MNOTIFY_ENDPOINT}?key=${encodeURIComponent(
        MNOTIFY_API_KEY
      )}`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          recipient: [recipient],
          sender,
          message,
          is_schedule: false,
          schedule_date: ""
        })
      }
    );

  const responseText =
    await response.text();

  if (!response.ok) {
    throw new Error(
      `mNotify request failed with HTTP ${response.status}.`
    );
  }

  let result = null;

  try {
    result =
      JSON.parse(responseText);
  } catch {
    result = null;
  }

  /*
   * mNotify normally returns a JSON response.
   * Do not log the complete response because it
   * could contain unnecessary customer information.
   */
  return {
    success: true,
    providerResponse:
      result?.status === false
        ? "provider_reported_failure"
        : "accepted"
  };
}

module.exports = async function handler(
  req,
  res
) {
  applySecurityHeaders(res);

  if (req.method !== "POST") {
    res.setHeader(
      "Allow",
      "POST"
    );

    return res.status(405).json({
      success: false,
      message:
        "Method not allowed."
    });
  }

  try {
    /*
     * Paystack signs the ORIGINAL request body.
     * Therefore we must read the raw body before
     * parsing JSON.
     */
    const rawBody =
      await readRawBody(req);

    const signature =
      req.headers[
        "x-paystack-signature"
      ];

    if (
      !verifyPaystackSignature(
        rawBody,
        signature
      )
    ) {
      return res.status(401).json({
        success: false,
        message:
          "Invalid webhook signature."
      });
    }

    let payload;

    try {
      payload =
        JSON.parse(rawBody);
    } catch {
      return res.status(400).json({
        success: false,
        message:
          "Invalid JSON payload."
      });
    }

    /*
     * We only process successful charges.
     */
    if (
      payload?.event !==
      "charge.success"
    ) {
      return res.status(200).json({
        success: true,
        message:
          "Event acknowledged."
      });
    }

    const data =
      payload.data || {};

    const reference =
      firstValue(
        data.reference,
        data.transaction_reference
      );

    if (!reference) {
      return res.status(400).json({
        success: false,
        message:
          "Payment reference is missing."
      });
    }

    const amount =
      Number(data.amount);

    if (
      !Number.isInteger(amount) ||
      amount < 0
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Invalid payment amount."
      });
    }

    /*
     * We expect Ghana cedi payments.
     */
    const currency =
      String(
        data.currency || ""
      ).toUpperCase();

    if (currency !== "GHS") {
      return res.status(400).json({
        success: false,
        message:
          "Unsupported payment currency."
      });
    }

    const supabase =
      createSupabase();

    /*
     * Idempotency check.
     *
     * Paystack can retry webhook events.
     * paystack_ref is UNIQUE in our database.
     */
    const {
      data: existingTransaction,
      error: existingError
    } = await supabase
      .from("transactions")
      .select(
        "id, status, voucher_code"
      )
      .eq(
        "paystack_ref",
        String(reference)
      )
      .maybeSingle();

    if (existingError) {
      logServerError(
        "webhook-existing-transaction",
        existingError
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to check payment."
      });
    }

    if (existingTransaction) {
      return res.status(200).json({
        success: true,
        message:
          "Payment already processed.",
        status:
          existingTransaction.status
      });
    }

    const agentIdentifier =
      getAgentIdentifier(data);

    const terminalIdentifier =
      getTerminalIdentifier(data);

    /*
     * IMPORTANT:
     * There is intentionally NO
     * "single agent fallback".
     *
     * A payment must identify its agent.
     */
    const agent =
      await findAgent(
        supabase,
        agentIdentifier,
        terminalIdentifier
      );

    if (!agent) {
      return res.status(200).json({
        success: true,
        message:
          "Payment received but agent could not be matched."
      });
    }

    const packageId =
      getPackageId(data);

    let packageData = null;

    /*
     * First preference:
     * explicitly supplied package_id.
     */
    if (packageId) {
      const {
        data: packageById,
        error: packageError
      } = await supabase
        .from("packages")
        .select(
          "id, agent_id, package_name, price_in_pesewas"
        )
        .eq(
          "id",
          String(packageId)
        )
        .eq(
          "agent_id",
          agent.agent_id
        )
        .maybeSingle();

      if (packageError) {
        logServerError(
          "webhook-package-id",
          packageError
        );

        return res.status(500).json({
          success: false,
          message:
            "Unable to find package."
        });
      }

      packageData =
        packageById || null;
    }

    /*
     * Fallback:
     * match the authenticated agent's package
     * using the exact Paystack amount.
     */
    if (!packageData) {
      const {
        data: packages,
        error: packageError
      } = await supabase
        .from("packages")
        .select(
          "id, agent_id, package_name, price_in_pesewas"
        )
        .eq(
          "agent_id",
          agent.agent_id
        )
        .eq(
          "price_in_pesewas",
          amount
        );

      if (packageError) {
        logServerError(
          "webhook-package-amount",
          packageError
        );

        return res.status(500).json({
          success: false,
          message:
            "Unable to match package."
        });
      }

      if (
        packages &&
        packages.length === 1
      ) {
        packageData =
          packages[0];
      }
    }

    if (!packageData) {
      return res.status(200).json({
        success: true,
        message:
          "Payment received but package could not be matched."
      });
    }

    /*
     * Atomically allocate exactly one voucher.
     *
     * The database RPC uses FOR UPDATE SKIP LOCKED,
     * preventing two simultaneous payments from
     * receiving the same voucher.
     */
    const {
      data: allocatedRows,
      error: allocationError
    } = await supabase.rpc(
      "allocate_voucher",
      {
        p_agent_id:
          agent.agent_id,

        p_package_id:
          packageData.id
      }
    );

    if (allocationError) {
      logServerError(
        "webhook-voucher-allocation",
        allocationError
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to allocate voucher."
      });
    }

    const allocated =
      allocatedRows?.[0];

    if (!allocated) {
      const {
        error: transactionError
      } = await supabase
        .from("transactions")
        .insert({
          paystack_ref:
            String(reference),

          agent_id:
            agent.agent_id,

          package_id:
            packageData.id,

          customer_phone:
            getCustomerPhone(data) ||
            "unknown",

          amount_paid:
            amount,

          voucher_code:
            null,

          sms_status:
            "not_sent",

          status:
            "out_of_stock"
        });

      if (transactionError) {
        logServerError(
          "webhook-out-of-stock-transaction",
          transactionError
        );
      }

      return res.status(200).json({
        success: true,
        message:
          "Payment received but no voucher is available."
      });
    }

    const customerPhone =
      getCustomerPhone(data);

    let smsStatus =
      "not_sent";

    if (customerPhone) {
      try {
        await sendVoucherSms({
          recipient:
            customerPhone,

          voucherCode:
            allocated.voucher_code,

          packageName:
            packageData.package_name,

          reference:
            String(reference)
        });

        smsStatus =
          "sent";

      } catch (smsError) {
        logServerError(
          "webhook-sms",
          smsError
        );

        smsStatus =
          "failed";
      }
    }

    const {
      error: transactionError
    } = await supabase
      .from("transactions")
      .insert({
        paystack_ref:
          String(reference),

        agent_id:
          agent.agent_id,

        package_id:
          packageData.id,

        customer_phone:
          customerPhone ||
          "unknown",

        amount_paid:
          amount,

        voucher_code:
          allocated.voucher_code,

        sms_status:
          smsStatus,

        status:
          "success"
      });

    if (transactionError) {
      /*
       * The voucher has already been allocated.
       * Do not allocate another voucher.
       *
       * The UNIQUE paystack_ref constraint protects
       * against duplicate transaction records.
       */
      logServerError(
        "webhook-transaction-insert",
        transactionError
      );

      return res.status(500).json({
        success: false,
        message:
          "Voucher allocated but transaction logging failed."
      });
    }

    return res.status(200).json({
      success: true,
      message:
        "Payment processed successfully."
    });

  } catch (error) {
    logServerError(
      "paystack-webhook",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Webhook processing failed."
    });
  }
};
