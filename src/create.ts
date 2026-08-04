/** Issuing a root SD-JWT and signing delegation hops. */
import { encodeBase64Url, encodeStringBase64Url } from './base64url.js';
import { computeBinding, computeDisclosureDigest } from './binding.js';
import { DelegateSdJwtError } from './errors.js';
import {
  CLAIM_ARRAY_DISCLOSURE,
  CLAIM_AUD,
  CLAIM_CNF,
  CLAIM_DELEGATE_PAYLOAD,
  CLAIM_IAT,
  CLAIM_NONCE,
  CLAIM_SD_ALG,
  DEFAULT_SALT_BYTES,
  DEFAULT_SD_ALG,
  DISCLOSURE_SEPARATOR,
  SUPPORTED_SD_ALGS,
  TYP_INTERMEDIATE,
  TYP_TERMINAL,
} from './format.js';
import { ParsedToken, parseToken } from './parse.js';
import type { Hasher, HashMode, JsonObject, SaltGenerator, Signer } from './types.js';

/**
 * Build a raw disclosure string: `base64url(JSON([salt, value]))` for an array
 * element, or `base64url(JSON([salt, name, value]))` for an object property.
 */
export function createDisclosure(
  value: unknown,
  saltGenerator: SaltGenerator,
  name?: string,
  saltBytes: number = DEFAULT_SALT_BYTES,
): string {
  const salt = encodeBase64Url(saltGenerator(saltBytes));
  const parts = name === undefined ? [salt, value] : [salt, name, value];
  return encodeStringBase64Url(JSON.stringify(parts));
}

async function signCompact(
  header: JsonObject,
  payload: JsonObject,
  signer: Signer,
): Promise<string> {
  const signingInput =
    encodeStringBase64Url(JSON.stringify(header)) +
    '.' +
    encodeStringBase64Url(JSON.stringify(payload));
  const signature = await signer(signingInput);
  if (typeof signature !== 'string' || signature.length === 0) {
    throw new DelegateSdJwtError('Signer must return a non-empty base64url signature');
  }
  return `${signingInput}.${signature}`;
}

function assertSdAlg(sdAlg: string): void {
  if (!SUPPORTED_SD_ALGS.includes(sdAlg)) {
    throw new DelegateSdJwtError(`Unsupported ${CLAIM_SD_ALG}: ${JSON.stringify(sdAlg)}`);
  }
}

function buildHeader(alg: string, typ: string | undefined, kid: string | undefined, extra?: JsonObject): JsonObject {
  if (typeof alg !== 'string' || alg.length === 0 || alg.toLowerCase() === 'none') {
    throw new DelegateSdJwtError(`Invalid signing 'alg': ${JSON.stringify(alg)}`);
  }
  const header: JsonObject = { alg };
  if (typ !== undefined) header['typ'] = typ;
  if (kid !== undefined) header['kid'] = kid;
  return { ...header, ...extra };
}

export interface CreateRootSdJwtOptions {
  /** Claims that become the single `delegate_payload` element. */
  claims: JsonObject;
  /** JWS algorithm written to the header; must match `signer`. */
  alg: string;
  signer: Signer;
  hasher: Hasher;
  saltGenerator: SaltGenerator;
  kid?: string;
  /** Top-level claims, e.g. `iss`, `exp`, or the holder's `cnf`. */
  extraClaims?: JsonObject;
  /** Extra header parameters, e.g. `typ` or `x5c`. */
  extraHeader?: JsonObject;
  sdAlg?: string;
  saltBytes?: number;
}

/**
 * Issue a root SD-JWT whose `claims` are wrapped in a selectively-disclosable
 * `delegate_payload` array, so that the same resolution logic applies to the
 * root and to every hop.
 *
 * Any RFC 9901 SD-JWT works as a chain root — an SD-JWT VC issued elsewhere
 * needs no re-issuance. This helper exists for the case where the root is
 * itself a delegation grant.
 *
 * The root must expose the holder's key as `cnf.jwk`, either top-level via
 * `extraClaims` or inside `claims`.
 */
export async function createRootSdJwt(options: CreateRootSdJwtOptions): Promise<string> {
  const sdAlg = options.sdAlg ?? DEFAULT_SD_ALG;
  assertSdAlg(sdAlg);
  const disclosure = createDisclosure(
    options.claims,
    options.saltGenerator,
    undefined,
    options.saltBytes,
  );
  const digest = await computeDisclosureDigest(disclosure, sdAlg, options.hasher);
  const payload: JsonObject = {
    [CLAIM_SD_ALG]: sdAlg,
    ...options.extraClaims,
    [CLAIM_DELEGATE_PAYLOAD]: [{ [CLAIM_ARRAY_DISCLOSURE]: digest }],
  };
  const header = buildHeader(options.alg, undefined, options.kid, options.extraHeader);
  const jwt = await signCompact(header, payload, options.signer);
  return jwt + DISCLOSURE_SEPARATOR + disclosure + DISCLOSURE_SEPARATOR;
}

export interface CreateKbSdJwtOptions {
  /** The token being delegated: a compact SD-JWT or an already parsed one. */
  prevToken: string | ParsedToken;
  /**
   * The delegate payload for this hop. Include `cnf: { jwk }` to delegate
   * onward (`typ: kb+sd-jwt+kb`); omit it for a terminal hop (`typ: kb+sd-jwt`).
   * A short `exp` is the recommended mitigation for the lack of delegation
   * revocation (draft §8.3).
   */
  claims: JsonObject;
  aud: string;
  nonce: string;
  /** JWS algorithm written to the header; must match `signer`. */
  alg: string;
  /** Signs with the key named by the previous hop's `cnf.jwk`. */
  signer: Signer;
  hasher: Hasher;
  saltGenerator: SaltGenerator;
  kid?: string;
  /** `sd_hash` (default) binds JWT + disclosures; `issuer_jwt_hash` binds only the JWT. */
  hashMode?: HashMode;
  /** Issuance time in seconds; defaults to now. */
  iat?: number;
  sdAlg?: string;
  saltBytes?: number;
}

/**
 * Sign one delegation hop as a KB-SD-JWT bound to `prevToken`.
 *
 * The resulting token is a compact SD-JWT; join hops with
 * {@link serializeChain} to produce a dSD-JWT.
 */
export async function createKbSdJwt(options: CreateKbSdJwtOptions): Promise<string> {
  if (typeof options.aud !== 'string' || options.aud.length === 0) {
    throw new DelegateSdJwtError(`'${CLAIM_AUD}' is required for a KB-SD-JWT hop`);
  }
  if (typeof options.nonce !== 'string' || options.nonce.length === 0) {
    throw new DelegateSdJwtError(`'${CLAIM_NONCE}' is required for a KB-SD-JWT hop`);
  }

  const prevToken =
    typeof options.prevToken === 'string' ? parseToken(options.prevToken) : options.prevToken;
  const sdAlg = options.sdAlg ?? DEFAULT_SD_ALG;
  assertSdAlg(sdAlg);

  const binding = await computeBinding(prevToken, options.hashMode ?? 'sd_hash', options.hasher);
  const disclosure = createDisclosure(
    options.claims,
    options.saltGenerator,
    undefined,
    options.saltBytes,
  );
  const digest = await computeDisclosureDigest(disclosure, sdAlg, options.hasher);

  const payload: JsonObject = {
    [CLAIM_SD_ALG]: sdAlg,
    [CLAIM_IAT]: options.iat ?? Math.floor(Date.now() / 1000),
    [CLAIM_AUD]: options.aud,
    [CLAIM_NONCE]: options.nonce,
    [binding.claim]: binding.value,
    [CLAIM_DELEGATE_PAYLOAD]: [{ [CLAIM_ARRAY_DISCLOSURE]: digest }],
  };

  const typ = CLAIM_CNF in options.claims ? TYP_INTERMEDIATE : TYP_TERMINAL;
  const header = buildHeader(options.alg, typ, options.kid);
  const jwt = await signCompact(header, payload, options.signer);
  return jwt + DISCLOSURE_SEPARATOR + disclosure + DISCLOSURE_SEPARATOR;
}
