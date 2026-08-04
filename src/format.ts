/**
 * Every wire-format constant of Delegate SD-JWT lives here and nowhere else.
 *
 * draft-gco-oauth-delegate-sd-jwt is at `-00` (individual draft, pre-adoption).
 * The `typ` values and the `~~` chain framing are the members most likely to
 * change, so application code must never hard-code them: import from here.
 */
import { DelegateSdJwtError } from './errors.js';
import type { JsonObject } from './types.js';

/** RFC 9901 separator between an SD-JWT's JWT, its disclosures, and its KB-JWT. */
export const DISCLOSURE_SEPARATOR = '~';

/**
 * Separator between two tokens of a dSD-JWT chain. It is an *empty* disclosure
 * component: `<sd-jwt>~<disclosure>~~<kb-sd-jwt>~<disclosure>~`.
 */
export const CHAIN_SEPARATOR = DISCLOSURE_SEPARATOR + DISCLOSURE_SEPARATOR;

/** `typ` of a terminal hop — the delegate payload MUST NOT contain `cnf`. */
export const TYP_TERMINAL = 'kb+sd-jwt';

/** `typ` of an intermediate hop — the delegate payload MUST contain `cnf`. */
export const TYP_INTERMEDIATE = 'kb+sd-jwt+kb';

/** Accepted terminal `typ` values, including the legacy `kb-sd-jwt` alias. */
export const TERMINAL_TYPS: readonly string[] = [TYP_TERMINAL, 'kb-sd-jwt'];

/** Accepted intermediate `typ` values, including the legacy alias. */
export const INTERMEDIATE_TYPS: readonly string[] = [TYP_INTERMEDIATE, 'kb-sd-jwt+kb'];

/** RFC 9901 digest array of an object. */
export const CLAIM_SD = '_sd';

/** RFC 9901 hash algorithm claim. */
export const CLAIM_SD_ALG = '_sd_alg';

/** RFC 9901 array-element disclosure reference key. */
export const CLAIM_ARRAY_DISCLOSURE = '...';

/** Delegated payload array of a KB-SD-JWT. */
export const CLAIM_DELEGATE_PAYLOAD = 'delegate_payload';

/** Binding over the preceding token's full SD-JWT (JWT + disclosures). */
export const CLAIM_SD_HASH = 'sd_hash';

/** Binding over only the preceding token's signed JWT. */
export const CLAIM_ISSUER_JWT_HASH = 'issuer_jwt_hash';

/** Key confirmation claim naming the next hop's key. */
export const CLAIM_CNF = 'cnf';

export const CLAIM_IAT = 'iat';
export const CLAIM_EXP = 'exp';
export const CLAIM_AUD = 'aud';
export const CLAIM_NONCE = 'nonce';

/** `_sd_alg` assumed when the claim is absent (RFC 9901 §4.1.1). */
export const DEFAULT_SD_ALG = 'sha-256';

/** The only `_sd_alg` values this library accepts. */
export const SUPPORTED_SD_ALGS: readonly string[] = ['sha-256', 'sha-384', 'sha-512'];

/** Default tolerance for `exp` / `iat` comparisons, in seconds. */
export const DEFAULT_CLOCK_SKEW_SECONDS = 300;

/** Default disclosure salt length, in bytes (RFC 9901 §4.2.1 recommends ≥128 bits). */
export const DEFAULT_SALT_BYTES = 16;

/**
 * Read and validate a token's `_sd_alg`.
 *
 * @throws DelegateSdJwtError if present but not a supported algorithm name.
 */
export function resolveSdAlg(payload: JsonObject): string {
  const raw = payload[CLAIM_SD_ALG];
  if (raw === undefined) return DEFAULT_SD_ALG;
  if (typeof raw !== 'string' || !SUPPORTED_SD_ALGS.includes(raw)) {
    throw new DelegateSdJwtError(`Unsupported ${CLAIM_SD_ALG}: ${JSON.stringify(raw)}`);
  }
  return raw;
}

/** True when `typ` names a terminal KB-SD-JWT hop. */
export function isTerminalTyp(typ: string | null): boolean {
  return typ !== null && TERMINAL_TYPS.includes(typ);
}

/** True when `typ` names an intermediate KB-SD-JWT hop. */
export function isIntermediateTyp(typ: string | null): boolean {
  return typ !== null && INTERMEDIATE_TYPS.includes(typ);
}
