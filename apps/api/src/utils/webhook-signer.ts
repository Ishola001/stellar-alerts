import crypto from 'crypto';
import type Redis from 'ioredis';
import { redis } from '../lib/redis';
import { checkAndStoreNonce, generateNonce } from '../lib/nonceCache';

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
}

export interface ParsedWebhookHeader {
  timestamp: number;
  nonce: string;
  signature: string;
}

export type WebhookVerificationHttpStatus = 200 | 400 | 401;

export interface WebhookVerificationResult {
  status: WebhookVerificationHttpStatus;
  valid: boolean;
  error?: string;
}

export const DEFAULT_DRIFT_TOLERANCE_MS = 300000; // 5 minutes
export const MAX_WEBHOOK_HEADER_LENGTH = 8192;
export const MAX_WEBHOOK_PAYLOAD_LENGTH = 1024 * 1024;
const SIGNATURE_HEX_REGEX = /^[0-9a-fA-F]{64}$/;
const CONTROL_CHAR_REGEX = /[\u0000-\u001F\u007F]/;
const MAX_NONCE_LENGTH = 128;

function normalizePayload(payload: unknown): string {
  if (payload === null || payload === undefined) {
    return '';
  }
  if (typeof payload !== 'string') {
    return String(payload);
  }
  return payload;
}

function safeTimingSafeEqual(left: string, right: string): boolean {
  try {
    const leftBuffer = Buffer.from(left, 'utf8');
    const rightBuffer = Buffer.from(right, 'utf8');

    if (leftBuffer.length !== rightBuffer.length) {
      return false;
    }

    if (leftBuffer.length === 0) {
      return true;
    }

    return crypto.timingSafeEqual(leftBuffer, rightBuffer);
  } catch {
    return false;
  }
}

/**
 * Parses and validates the structure of an X-Stellar-Signature header value.
 * Returns a structured error for malformed headers that should be rejected with HTTP 400.
 */
export function parseWebhookSignatureHeader(
  headerValue: unknown
): { ok: true; parsed: ParsedWebhookHeader } | { ok: false; reason: string } {
  if (headerValue === null || headerValue === undefined) {
    return { ok: false, reason: 'Missing signature header' };
  }

  if (typeof headerValue !== 'string') {
    return { ok: false, reason: 'Signature header must be a string' };
  }

  if (headerValue.length === 0) {
    return { ok: false, reason: 'Empty signature header' };
  }

  if (headerValue.length > MAX_WEBHOOK_HEADER_LENGTH) {
    return { ok: false, reason: 'Signature header exceeds maximum length' };
  }

  if (CONTROL_CHAR_REGEX.test(headerValue)) {
    return { ok: false, reason: 'Signature header contains control characters' };
  }

  if (!headerValue.includes('t=') || !headerValue.includes('v1=')) {
    return { ok: false, reason: 'Missing required signature fields' };
  }

  const parts = headerValue.split(',');
  if (parts.length < 2 || parts.length > 3) {
    return { ok: false, reason: 'Invalid signature header segment count' };
  }

  let timestampPart: string | undefined;
  let noncePart: string | undefined;
  let signaturePart: string | undefined;

  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) {
      return { ok: false, reason: 'Empty signature header segment' };
    }

    if (trimmed.startsWith('t=')) {
      if (timestampPart) {
        return { ok: false, reason: 'Duplicate timestamp field' };
      }
      timestampPart = trimmed;
      continue;
    }

    if (trimmed.startsWith('n=')) {
      if (noncePart) {
        return { ok: false, reason: 'Duplicate nonce field' };
      }
      noncePart = trimmed;
      continue;
    }

    if (trimmed.startsWith('v1=')) {
      if (signaturePart) {
        return { ok: false, reason: 'Duplicate signature field' };
      }
      signaturePart = trimmed;
      continue;
    }

    return { ok: false, reason: 'Unknown signature header segment' };
  }

  if (!timestampPart || !signaturePart) {
    return { ok: false, reason: 'Missing required signature fields' };
  }

  const timestampRaw = timestampPart.slice(2);
  if (!/^\d+$/.test(timestampRaw)) {
    return { ok: false, reason: 'Invalid timestamp format' };
  }

  const timestamp = Number(timestampRaw);
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0) {
    return { ok: false, reason: 'Invalid timestamp value' };
  }

  const signature = signaturePart.slice(3);
  if (!SIGNATURE_HEX_REGEX.test(signature)) {
    return { ok: false, reason: 'Invalid signature format' };
  }

  const nonce = noncePart ? noncePart.slice(2) : '';
  if (nonce.length > MAX_NONCE_LENGTH) {
    return { ok: false, reason: 'Nonce exceeds maximum length' };
  }

  if (nonce && CONTROL_CHAR_REGEX.test(nonce)) {
    return { ok: false, reason: 'Nonce contains control characters' };
  }

  return {
    ok: true,
    parsed: {
      timestamp,
      nonce,
      signature,
    },
  };
}

function validatePayload(payload: unknown): { ok: true; payload: string } | { ok: false; reason: string } {
  const normalized = normalizePayload(payload);

  if (normalized.length > MAX_WEBHOOK_PAYLOAD_LENGTH) {
    return { ok: false, reason: 'Payload exceeds maximum length' };
  }

  return { ok: true, payload: normalized };
}

function verifyParsedSignature(
  payload: string,
  parsed: ParsedWebhookHeader,
  secret: string,
  toleranceMs: number,
  nonceOverride?: string
): boolean {
  const nonce = parsed.nonce || nonceOverride || '';

  if (Math.abs(Date.now() - parsed.timestamp) > toleranceMs) {
    return false;
  }

  const expected = generateWebhookSignature(payload, secret, parsed.timestamp, nonce);
  if (safeTimingSafeEqual(parsed.signature, expected.signature)) {
    return true;
  }

  if (!parsed.nonce && !nonceOverride) {
    const legacyExpected = generateWebhookSignature(payload, secret, parsed.timestamp, '');
    return safeTimingSafeEqual(parsed.signature, legacyExpected.signature);
  }

  return false;
}

/**
 * Evaluates webhook verification and maps the outcome to an HTTP status code.
 * Malformed headers -> 400, invalid signatures -> 401, valid -> 200.
 */
export function evaluateWebhookVerification(
  payload: unknown,
  headerValue: unknown,
  secret: unknown,
  optionsOrTolerance: number | VerifyWebhookOptions = DEFAULT_DRIFT_TOLERANCE_MS
): WebhookVerificationResult {
  const payloadResult = validatePayload(payload);
  if (!payloadResult.ok) {
    return { status: 400, valid: false, error: payloadResult.reason };
  }

  if (typeof secret !== 'string' || secret.length === 0) {
    return { status: 400, valid: false, error: 'Invalid webhook secret' };
  }

  const parseResult = parseWebhookSignatureHeader(headerValue);
  if (!parseResult.ok) {
    return { status: 400, valid: false, error: parseResult.reason };
  }

  const options: VerifyWebhookOptions =
    typeof optionsOrTolerance === 'number'
      ? { toleranceMs: optionsOrTolerance }
      : (optionsOrTolerance ?? {});

  const toleranceMs = options.toleranceMs ?? DEFAULT_DRIFT_TOLERANCE_MS;
  const isValid = verifyParsedSignature(
    payloadResult.payload,
    parseResult.parsed,
    secret,
    toleranceMs,
    options.nonce
  );

  if (!isValid) {
    return { status: 401, valid: false, error: 'Invalid webhook signature' };
  }

  return { status: 200, valid: true };
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
  const hmac = crypto.createHmac('sha256', secret);
  const dataToSign = nonce ? `${timestamp}.${nonce}.${payload}` : `${timestamp}.${payload}`;
  const signature = hmac.update(dataToSign).digest('hex');
  const headerValue = nonce
    ? `t=${timestamp},n=${nonce},v1=${signature}`
    : `t=${timestamp},v1=${signature}`;

  return {
    signature,
    timestamp,
    nonce,
    headerValue,
  };
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
  try {
    const options: VerifyWebhookOptions =
      typeof optionsOrTolerance === 'number'
        ? { toleranceMs: optionsOrTolerance }
        : (optionsOrTolerance ?? {});

    const toleranceMs = options.toleranceMs ?? DEFAULT_DRIFT_TOLERANCE_MS;
    const checkReplay = options.checkReplay ?? true;
    const redisClient = options.redisClient ?? redis;

    const payloadResult = validatePayload(payload);
    if (!payloadResult.ok) {
      return false;
    }

    const parseResult = parseWebhookSignatureHeader(headerValue);
    if (!parseResult.ok) {
      return false;
    }

    const isValid = verifyParsedSignature(
      payloadResult.payload,
      parseResult.parsed,
      secret,
      toleranceMs,
      options.nonce
    );

    if (!isValid) {
      return false;
    }

    const nonce = parseResult.parsed.nonce || options.nonce || '';
    if (nonce && checkReplay) {
      const ttlSeconds = Math.max(1, Math.ceil(toleranceMs / 1000));
      const isFresh = await checkAndStoreNonce(nonce, ttlSeconds, redisClient);
      if (!isFresh) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
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
  try {
    const payloadResult = validatePayload(payload);
    if (!payloadResult.ok) {
      return false;
    }

    const parseResult = parseWebhookSignatureHeader(headerValue);
    if (!parseResult.ok) {
      return false;
    }

    return verifyParsedSignature(
      payloadResult.payload,
      parseResult.parsed,
      secret,
      toleranceMs,
      nonceOverride
    );
  } catch {
    return false;
  }
}
