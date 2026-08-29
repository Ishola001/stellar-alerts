import crypto from 'crypto';
import type Redis from 'ioredis';
import { redis } from '../lib/redis';
import { checkAndStoreNonce, generateNonce } from '../lib/nonceCache';
import {
  createKmsWebhookSigner,
  KmsHmacClient,
  KmsProvider,
  KmsWebhookSigner,
} from './kms-signer';

export interface WebhookHeaderResult {
  signature: string;
  timestamp: number;
  nonce: string;
  headerValue: string;
}

export interface VerifyWebhookOptions {
  toleranceMs?: number;
  nonce?: string;
  checkReplay?: boolean;
  redisClient?: Redis;
  kmsSigner?: KmsWebhookSigner;
}

export interface SignWebhookPayloadOptions {
  secret?: string;
  timestamp?: number;
  nonce?: string;
  kmsSigner?: KmsWebhookSigner;
  kmsKeyId?: string;
}

export interface KmsWebhookSigningEnv {
  enabled: boolean;
  provider?: KmsProvider;
  primaryKeyId?: string;
  previousKeyIds?: string[];
}

export const DEFAULT_DRIFT_TOLERANCE_MS = 300000; // 5 minutes

let configuredKmsSigner: KmsWebhookSigner | null = null;

export function buildWebhookDataToSign(
  payload: string,
  timestamp: number,
  nonce: string
): string {
  return nonce ? `${timestamp}.${nonce}.${payload}` : `${timestamp}.${payload}`;
}

export function buildWebhookHeaderValue(
  timestamp: number,
  nonce: string,
  signature: string
): string {
  return nonce
    ? `t=${timestamp},n=${nonce},v1=${signature}`
    : `t=${timestamp},v1=${signature}`;
}

export function parseKmsWebhookSigningEnv(env: NodeJS.ProcessEnv = process.env): KmsWebhookSigningEnv {
  const enabled = env.KMS_WEBHOOK_SIGNING_ENABLED === 'true';
  const previousKeyIds = env.KMS_PREVIOUS_KEY_IDS
    ? env.KMS_PREVIOUS_KEY_IDS.split(',').map((keyId) => keyId.trim()).filter(Boolean)
    : [];

  return {
    enabled,
    provider: env.KMS_PROVIDER as KmsProvider | undefined,
    primaryKeyId: env.KMS_PRIMARY_KEY_ID,
    previousKeyIds,
  };
}

export function configureKmsWebhookSigner(
  client: KmsHmacClient,
  env: NodeJS.ProcessEnv = process.env
): KmsWebhookSigner | null {
  const kmsEnv = parseKmsWebhookSigningEnv(env);
  if (!kmsEnv.enabled || !kmsEnv.provider || !kmsEnv.primaryKeyId) {
    configuredKmsSigner = null;
    return null;
  }

  configuredKmsSigner = createKmsWebhookSigner({
    provider: kmsEnv.provider,
    primaryKeyId: kmsEnv.primaryKeyId,
    previousKeyIds: kmsEnv.previousKeyIds,
    client,
  });

  return configuredKmsSigner;
}

export function getConfiguredKmsWebhookSigner(): KmsWebhookSigner | null {
  return configuredKmsSigner;
}

export function resetConfiguredKmsWebhookSigner(): void {
  configuredKmsSigner = null;
}

function computeLocalHmacSignature(dataToSign: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(dataToSign).digest('hex');
}

/**
 * Generates an HMAC SHA256 signature for a webhook payload with a UUIDv4 nonce
 * and Unix timestamp to prevent payload spoofing and replay attacks.
 *
 * @param payload   - The JSON payload string to sign.
 * @param secret    - The shared webhook signing secret.
 * @param timestamp - The Unix timestamp (milliseconds). Defaults to Date.now().
 * @param nonce     - The UUIDv4 nonce string. Defaults to a new cryptographically random UUID.
 */
export function generateWebhookSignature(
  payload: string,
  secret: string,
  timestamp: number = Date.now(),
  nonce: string = generateNonce()
): WebhookHeaderResult {
  const dataToSign = buildWebhookDataToSign(payload, timestamp, nonce);
  const signature = computeLocalHmacSignature(dataToSign, secret);
  const headerValue = buildWebhookHeaderValue(timestamp, nonce, signature);

  return {
    signature,
    timestamp,
    nonce,
    headerValue,
  };
}

/**
 * Generates a webhook signature using a hardware-backed KMS/HSM key.
 * The raw signing key never enters application memory.
 */
export async function generateWebhookSignatureKms(
  payload: string,
  kmsSigner: KmsWebhookSigner,
  timestamp: number = Date.now(),
  nonce: string = generateNonce()
): Promise<WebhookHeaderResult> {
  const dataToSign = buildWebhookDataToSign(payload, timestamp, nonce);
  const signature = await kmsSigner.signHmacSha256(dataToSign);
  const headerValue = buildWebhookHeaderValue(timestamp, nonce, signature);

  return {
    signature,
    timestamp,
    nonce,
    headerValue,
  };
}

/**
 * Signs a webhook payload using KMS when configured, otherwise falls back to the local secret.
 */
export async function signWebhookPayload(
  payload: string,
  options: SignWebhookPayloadOptions = {}
): Promise<WebhookHeaderResult> {
  const timestamp = options.timestamp ?? Date.now();
  const nonce = options.nonce ?? generateNonce();
  const kmsSigner = options.kmsSigner ?? configuredKmsSigner;

  if (kmsSigner) {
    return generateWebhookSignatureKms(payload, kmsSigner, timestamp, nonce);
  }

  if (!options.secret) {
    throw new Error('Webhook signing secret is required when KMS signing is disabled');
  }

  return generateWebhookSignature(payload, options.secret, timestamp, nonce);
}

/**
 * Verifies an incoming webhook signature header against a secret key, enforcing:
 * 1. Correct HMAC SHA256 signature matching payload, timestamp, and nonce.
 * 2. 5-minute clock drift tolerance (fails if request is older than 5 minutes or in future).
 * 3. Redis-backed nonce replay prevention (rejects previously processed nonces).
 *
 * @param payload            - The raw JSON payload received.
 * @param headerValue        - The value of X-Stellar-Signature (e.g. "t=...,n=...,v1=...").
 * @param secret             - The shared webhook secret.
 * @param optionsOrTolerance - Tolerance in ms (number) or VerifyWebhookOptions object.
 * @returns `true` if valid and fresh, `false` if forged, expired, or replayed.
 */
export async function verifyWebhookSignature(
  payload: string,
  headerValue: string,
  secret: string,
  optionsOrTolerance: number | VerifyWebhookOptions = DEFAULT_DRIFT_TOLERANCE_MS
): Promise<boolean> {
  const options: VerifyWebhookOptions =
    typeof optionsOrTolerance === 'number'
      ? { toleranceMs: optionsOrTolerance }
      : (optionsOrTolerance ?? {});

  const toleranceMs = options.toleranceMs ?? DEFAULT_DRIFT_TOLERANCE_MS;
  const checkReplay = options.checkReplay ?? true;
  const redisClient = options.redisClient ?? redis;
  const kmsSigner = options.kmsSigner ?? configuredKmsSigner;

  if (!headerValue || !headerValue.includes('t=') || !headerValue.includes('v1=')) {
    return false;
  }

  const parts = headerValue.split(',');
  const timestampPart = parts.find((p) => p.startsWith('t='));
  const noncePart = parts.find((p) => p.startsWith('n='));
  const signaturePart = parts.find((p) => p.startsWith('v1='));

  if (!timestampPart || !signaturePart) return false;

  const timestamp = parseInt(timestampPart.substring(2), 10);
  const signature = signaturePart.substring(3);
  const nonce = noncePart ? noncePart.substring(2) : (options.nonce || '');

  if (isNaN(timestamp)) return false;

  if (Math.abs(Date.now() - timestamp) > toleranceMs) {
    return false;
  }

  const dataToSign = buildWebhookDataToSign(payload, timestamp, nonce);
  let signatureValid = false;

  if (kmsSigner) {
    signatureValid = await kmsSigner.verifyHmacSha256(dataToSign, signature);

    if (!signatureValid && !noncePart && !options.nonce) {
      const legacyDataToSign = buildWebhookDataToSign(payload, timestamp, '');
      signatureValid = await kmsSigner.verifyHmacSha256(legacyDataToSign, signature);
    }
  } else {
    const expected = generateWebhookSignature(payload, secret, timestamp, nonce);
    const sigBuffer = Buffer.from(signature);
    const expBuffer = Buffer.from(expected.signature);

    if (sigBuffer.length === expBuffer.length && crypto.timingSafeEqual(sigBuffer, expBuffer)) {
      signatureValid = true;
    } else if (!noncePart && !options.nonce) {
      const legacyExpected = generateWebhookSignature(payload, secret, timestamp, '');
      const legacyExpBuffer = Buffer.from(legacyExpected.signature);
      signatureValid =
        sigBuffer.length === legacyExpBuffer.length &&
        crypto.timingSafeEqual(sigBuffer, legacyExpBuffer);
    }
  }

  if (!signatureValid) {
    return false;
  }

  if (nonce && checkReplay) {
    const ttlSeconds = Math.max(1, Math.ceil(toleranceMs / 1000));
    const isFresh = await checkAndStoreNonce(nonce, ttlSeconds, redisClient);
    if (!isFresh) {
      return false;
    }
  }

  return true;
}

/**
 * Synchronous verification helper for HMAC signature and timestamp drift only (without Redis check).
 */
export function verifyWebhookSignatureSync(
  payload: string,
  headerValue: string,
  secret: string,
  toleranceMs: number = DEFAULT_DRIFT_TOLERANCE_MS,
  nonceOverride?: string
): boolean {
  if (!headerValue || !headerValue.includes('t=') || !headerValue.includes('v1=')) {
    return false;
  }

  const parts = headerValue.split(',');
  const timestampPart = parts.find((p) => p.startsWith('t='));
  const noncePart = parts.find((p) => p.startsWith('n='));
  const signaturePart = parts.find((p) => p.startsWith('v1='));

  if (!timestampPart || !signaturePart) return false;

  const timestamp = parseInt(timestampPart.substring(2), 10);
  const signature = signaturePart.substring(3);
  const nonce = noncePart ? noncePart.substring(2) : (nonceOverride || '');

  if (isNaN(timestamp)) return false;

  if (Math.abs(Date.now() - timestamp) > toleranceMs) {
    return false;
  }

  const expected = generateWebhookSignature(payload, secret, timestamp, nonce);
  const sigBuffer = Buffer.from(signature);
  const expBuffer = Buffer.from(expected.signature);

  if (sigBuffer.length !== expBuffer.length || !crypto.timingSafeEqual(sigBuffer, expBuffer)) {
    if (!noncePart && !nonceOverride) {
      const legacyExpected = generateWebhookSignature(payload, secret, timestamp, '');
      const legacyExpBuffer = Buffer.from(legacyExpected.signature);
      return (
        sigBuffer.length === legacyExpBuffer.length &&
        crypto.timingSafeEqual(sigBuffer, legacyExpBuffer)
      );
    }
    return false;
  }

  return true;
}
