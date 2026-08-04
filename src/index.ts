/**
 * Delegate SD-JWT (dSD-JWT) — verifiable delegation chains over RFC 9901
 * SD-JWT, per draft-gco-oauth-delegate-sd-jwt-00.
 *
 * A credential holder delegates a down-scoped presentation to a delegate
 * holder (a person to an agent, an agent to another agent); a verifier
 * validates the whole chain back to the original issuer.
 */

export { DelegateSdJwtError } from './errors.js';

export type {
  Hasher,
  HashMode,
  Jwk,
  JsonObject,
  JwkVerifierFactory,
  RootVerifierResolver,
  SaltGenerator,
  Signer,
  UnverifiedToken,
  Verifier,
} from './types.js';

export { isPlainObject } from './types.js';

// Wire format. Import these instead of hard-coding `typ` values, claim names,
// or the `~~` separator: the draft is at -00 and these will move.
export {
  CHAIN_SEPARATOR,
  CLAIM_ARRAY_DISCLOSURE,
  CLAIM_AUD,
  CLAIM_CNF,
  CLAIM_DELEGATE_PAYLOAD,
  CLAIM_EXP,
  CLAIM_IAT,
  CLAIM_ISSUER_JWT_HASH,
  CLAIM_NONCE,
  CLAIM_SD,
  CLAIM_SD_ALG,
  CLAIM_SD_HASH,
  DEFAULT_CLOCK_SKEW_SECONDS,
  DEFAULT_SALT_BYTES,
  DEFAULT_SD_ALG,
  DISCLOSURE_SEPARATOR,
  INTERMEDIATE_TYPS,
  isIntermediateTyp,
  isTerminalTyp,
  resolveSdAlg,
  SUPPORTED_SD_ALGS,
  TERMINAL_TYPS,
  TYP_INTERMEDIATE,
  TYP_TERMINAL,
} from './format.js';

export { decodeJwtSegment, ParsedToken, parseToken } from './parse.js';

export {
  computeBinding,
  computeDisclosureDigest,
  computeIssuerJwtHash,
  computeSdHash,
  verifyBinding,
} from './binding.js';

export { normalizeDelegatePayload, resolveDisclosures } from './disclosures.js';

export { createDisclosure, createKbSdJwt, createRootSdJwt } from './create.js';
export type { CreateKbSdJwtOptions, CreateRootSdJwtOptions } from './create.js';

export { assertDelegateItemCount, verifyKbSdJwt, verifySdJwt } from './verify.js';
export type { VerifiedToken, VerifyKbSdJwtOptions, VerifySdJwtOptions } from './verify.js';

export { serializeChain, splitChain, verifyChain } from './chain.js';
export type { VerifiedChain, VerifyChainOptions } from './chain.js';

export {
  importEcPrivateKey,
  webcryptoHasher,
  webcryptoJwkVerifier,
  webcryptoSaltGenerator,
  webcryptoSigner,
} from './webcrypto.js';

export {
  decodeBase64Url,
  decodeBase64UrlToString,
  encodeBase64Url,
  encodeStringBase64Url,
  utf8Bytes,
} from './base64url.js';
