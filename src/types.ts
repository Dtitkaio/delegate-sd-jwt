/**
 * Injected-crypto contracts. This library performs no cryptography itself: the
 * caller supplies hashing, signing, and signature verification so that private
 * keys can stay inside a wallet / KMS / HSM and never enter this module.
 */

/** A JSON object with unknown member types. */
export type JsonObject = Record<string, unknown>;

/** Narrow an unknown value to a non-array JSON object. */
export function isPlainObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A JSON Web Key. Only `kty` is required; members vary by key type. */
export interface Jwk extends JsonObject {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  d?: string;
  kid?: string;
  alg?: string;
  use?: string;
}

/**
 * Hash `data` (an ASCII string) with an RFC 9901 `_sd_alg` name such as
 * `sha-256` and return the raw digest.
 */
export type Hasher = (data: string, alg: string) => Uint8Array | Promise<Uint8Array>;

/** Sign a JWS signing input (`header.payload`) and return a base64url signature. */
export type Signer = (signingInput: string) => string | Promise<string>;

/** Verify a base64url signature over a JWS signing input. */
export type Verifier = (signingInput: string, signatureB64Url: string) => boolean | Promise<boolean>;

/** Build a {@link Verifier} for a public JWK and a JWS `alg`. */
export type JwkVerifierFactory = (jwk: Jwk, alg: string) => Verifier | Promise<Verifier>;

/** Produce `byteLength` cryptographically random bytes for a disclosure salt. */
export type SaltGenerator = (byteLength: number) => Uint8Array;

/** The decoded header and payload of a token, before any verification. */
export interface UnverifiedToken {
  header: JsonObject;
  payload: JsonObject;
}

/**
 * Resolve the verification key for the root (issuer-signed) SD-JWT of a chain,
 * e.g. from `kid`, `x5c` plus trust roots, or a DID document.
 */
export type RootVerifierResolver = (token: UnverifiedToken) => Verifier | Promise<Verifier>;

/** Which claim binds a KB-SD-JWT to the token it delegates. */
export type HashMode = 'sd_hash' | 'issuer_jwt_hash';
