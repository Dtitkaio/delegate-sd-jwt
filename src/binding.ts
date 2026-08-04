/**
 * Hashes that bind one hop of a delegation chain to the previous one
 * (draft-gco-oauth-delegate-sd-jwt-00 §5.1.4).
 */
import { encodeBase64Url } from './base64url.js';
import { DelegateSdJwtError } from './errors.js';
import { CLAIM_ISSUER_JWT_HASH, CLAIM_SD_HASH } from './format.js';
import type { ParsedToken } from './parse.js';
import type { Hasher, HashMode, JsonObject } from './types.js';

async function hashAscii(value: string, alg: string, hasher: Hasher): Promise<string> {
  return encodeBase64Url(await hasher(value, alg));
}

/**
 * Hash a token's full SD-JWT — signed JWT plus disclosures plus the trailing
 * separator — excluding any detached KB-JWT. The hash algorithm is the hashed
 * token's own `_sd_alg`.
 */
export async function computeSdHash(token: ParsedToken, hasher: Hasher): Promise<string> {
  return hashAscii(token.sdJwt, token.sdAlg, hasher);
}

/**
 * Hash only a token's signed JWT, so the next delegate may redact the
 * preceding hop's disclosures without breaking the binding.
 */
export async function computeIssuerJwtHash(token: ParsedToken, hasher: Hasher): Promise<string> {
  return hashAscii(token.issuerJwt, token.sdAlg, hasher);
}

/** Hash a raw disclosure string into its RFC 9901 digest. */
export async function computeDisclosureDigest(
  disclosure: string,
  sdAlg: string,
  hasher: Hasher,
): Promise<string> {
  return hashAscii(disclosure, sdAlg, hasher);
}

/** Compute the binding claim name and value for `prevToken`. */
export async function computeBinding(
  prevToken: ParsedToken,
  hashMode: HashMode,
  hasher: Hasher,
): Promise<{ claim: string; value: string }> {
  if (hashMode === 'sd_hash') {
    return { claim: CLAIM_SD_HASH, value: await computeSdHash(prevToken, hasher) };
  }
  if (hashMode === 'issuer_jwt_hash') {
    return { claim: CLAIM_ISSUER_JWT_HASH, value: await computeIssuerJwtHash(prevToken, hasher) };
  }
  throw new DelegateSdJwtError(
    `hashMode must be '${CLAIM_SD_HASH}' or '${CLAIM_ISSUER_JWT_HASH}', got ${JSON.stringify(hashMode)}`,
  );
}

/**
 * Enforce that exactly one binding claim is present and that it matches
 * `prevToken`.
 *
 * Skipping either half of this check — presence *and* value — lets a malicious
 * delegate splice together hops from different chains when a holder `cnf` is
 * reused (draft §8.1).
 */
export async function verifyBinding(
  payload: JsonObject,
  prevToken: ParsedToken,
  hasher: Hasher,
): Promise<void> {
  const hasSdHash = CLAIM_SD_HASH in payload;
  const hasIssuerJwtHash = CLAIM_ISSUER_JWT_HASH in payload;
  if (hasSdHash === hasIssuerJwtHash) {
    throw new DelegateSdJwtError(
      `KB-SD-JWT payload must contain exactly one of '${CLAIM_SD_HASH}' or ` +
        `'${CLAIM_ISSUER_JWT_HASH}' (got ${CLAIM_SD_HASH}=${hasSdHash}, ` +
        `${CLAIM_ISSUER_JWT_HASH}=${hasIssuerJwtHash})`,
    );
  }
  const claim = hasSdHash ? CLAIM_SD_HASH : CLAIM_ISSUER_JWT_HASH;
  const actual = payload[claim];
  if (typeof actual !== 'string') {
    throw new DelegateSdJwtError(`KB-SD-JWT '${claim}' must be a string`);
  }
  const expected = hasSdHash
    ? await computeSdHash(prevToken, hasher)
    : await computeIssuerJwtHash(prevToken, hasher);
  if (actual !== expected) {
    throw new DelegateSdJwtError(`${claim} mismatch: expected '${expected}', got '${actual}'`);
  }
}
