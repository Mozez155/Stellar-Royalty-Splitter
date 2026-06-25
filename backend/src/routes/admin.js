import { Router } from "express";
import { z } from "zod";
import logger from "../logger.js";
import { validate, contractAddress, stellarAddress } from "../validation.js";
import { sendError, sendValidationError } from "../error-response.js";
import {
  isAdminRotateTokenValid,
  reloadSigningKeyFromSecretsFile,
  rotateSigningKey,
} from "../signing-key.js";
import { buildAndRecordTransaction } from "./_shared.js";
import { createApiKey, listApiKeys, revokeApiKey } from "../database/index.js";

export const adminRouter = Router();

const rotateKeySchema = z
  .object({
    secretKey: z
      .string()
      .regex(/^S[A-Z2-7]{55}$/, "Invalid Stellar secret key")
      .optional(),
    reloadFromFile: z.boolean().optional(),
  })
  .refine((body) => Boolean(body.secretKey) || body.reloadFromFile === true, {
    message: "Provide secretKey or set reloadFromFile to true",
  });

function extractBearerToken(req) {
  const header = req.get("Authorization");
  if (!header?.startsWith("Bearer ")) return null;
  return header.slice("Bearer ".length).trim();
}

function requireAdminRotateToken(req, res, next) {
  if (!process.env.ADMIN_ROTATE_TOKEN) {
    logger.warn("Admin rotate-key rejected: ADMIN_ROTATE_TOKEN not configured", {
      event: "signing_key_rotate_denied",
      reason: "token_not_configured",
    });
    return sendError(res, 503, "service_unavailable", "Key rotation is not configured on this server");
  }

  const token = extractBearerToken(req);
  if (!isAdminRotateTokenValid(token)) {
    logger.warn("Admin rotate-key rejected: invalid token", {
      event: "signing_key_rotate_denied",
      reason: "invalid_token",
    });
    return sendError(res, 401, "unauthorized", "Unauthorized");
  }

  next();
}

// ---------------------------------------------------------------------------
// Multi-sig admin management (#404)
// ---------------------------------------------------------------------------

const setAdminsSchema = z
  .object({
    contractId: contractAddress,
    walletAddress: stellarAddress,
    admins: z
      .array(stellarAddress)
      .min(1, "admins list must not be empty")
      .max(10, "admins list may not exceed 10 addresses"),
    threshold: z
      .number()
      .int()
      .min(1, "threshold must be at least 1"),
  })
  .refine((d) => d.threshold <= d.admins.length, {
    message: "threshold must not exceed the number of admins",
    path: ["threshold"],
  });

/**
 * POST /admin/set-admins
 * Configure the multi-sig admin list and signing threshold (#404).
 * Body: { contractId, walletAddress, admins: string[], threshold: number }
 * Default threshold is 2 (2-of-N multi-sig).
 */
adminRouter.post("/set-admins", validate(setAdminsSchema), async (req, res, next) => {
  try {
    const { contractId, walletAddress, admins, threshold = 2 } = req.body;

    if (threshold > admins.length) {
      return sendValidationError(res, [
        {
          field: "threshold",
          message: `threshold (${threshold}) must not exceed admins count (${admins.length})`,
          constraint: "max",
        },
      ]);
    }

    logger.info("set_admins requested", { contractId, adminCount: admins.length, threshold });

    const { addressToScVal, vecToScVal, u32ToScVal } = await import("../stellar.js");
    const adminsVec = vecToScVal(admins.map(addressToScVal));
    const thresholdVal = u32ToScVal(threshold);

    const { xdr, transactionId } = await buildAndRecordTransaction({
      contractId,
      walletAddress,
      transactionType: "initialize",
      scvlArgs: [adminsVec, thresholdVal],
      auditAction: "set_admins",
      auditMetadata: { adminCount: admins.length, threshold },
      transactionMetadata: { requestedAmount: null, tokenId: null },
      correlationId: req.correlationId,
    });

    res.json({ success: true, xdr, transactionId, adminCount: admins.length, threshold });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /admin/rotate-key
 * Body: { secretKey?: string, reloadFromFile?: boolean }
 * Header: Authorization: Bearer <ADMIN_ROTATE_TOKEN>
 */
adminRouter.post(
  "/rotate-key",
  requireAdminRotateToken,
  validate(rotateKeySchema),
  (req, res, next) => {
    try {
      const result = req.body.reloadFromFile
        ? reloadSigningKeyFromSecretsFile()
        : rotateSigningKey(req.body.secretKey, { source: "api" });

      res.json({
        publicKey: result.publicKey,
        rotatedAt: result.rotatedAt,
        source: result.source,
      });
    } catch (err) {
      next(err);
    }
  },
);

// ---------------------------------------------------------------------------
// API key management for per-key rate limiting (#420)
// ---------------------------------------------------------------------------

const generateKeySchema = z.object({
  label: z.string().max(100, "label must be 100 characters or fewer").optional(),
});

/**
 * POST /admin/generate-key
 * Issue a new API key. The raw key is returned only in this response —
 * only its hash is persisted, so it can never be retrieved again.
 * Body: { label?: string }
 * Header: Authorization: Bearer <ADMIN_ROTATE_TOKEN>
 */
adminRouter.post(
  "/generate-key",
  requireAdminRotateToken,
  validate(generateKeySchema),
  (req, res, next) => {
    try {
      const { id, apiKey, label, createdAt } = createApiKey(req.body.label);
      logger.info("API key generated", { event: "api_key_generated", id, label });
      res.json({ id, apiKey, label, createdAt });
    } catch (err) {
      next(err);
    }
  },
);

/**
 * GET /admin/keys
 * List API keys (never includes the raw key or its hash).
 * Header: Authorization: Bearer <ADMIN_ROTATE_TOKEN>
 */
adminRouter.get("/keys", requireAdminRotateToken, (_req, res, next) => {
  try {
    res.json({ keys: listApiKeys() });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /admin/keys/:id/revoke
 * Revoke an API key by id.
 * Header: Authorization: Bearer <ADMIN_ROTATE_TOKEN>
 */
adminRouter.post("/keys/:id/revoke", requireAdminRotateToken, (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id <= 0) {
      return sendError(res, 400, "bad_request", "id must be a positive integer");
    }

    const revoked = revokeApiKey(id);
    if (!revoked) {
      return sendError(res, 404, "not_found", "API key not found or already revoked");
    }

    logger.info("API key revoked", { event: "api_key_revoked", id });
    res.json({ success: true, id });
  } catch (err) {
    next(err);
  }
});
