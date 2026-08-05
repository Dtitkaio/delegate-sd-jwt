/** Per-token verification: root SD-JWTs and KB-SD-JWT delegation hops. */
import { verifyBinding } from './binding.js';
import { normalizeDelegatePayload, resolveDisclosures } from './disclosures.js';
import { DelegateSdJwtError } from './errors.js';
import {
  CLAIM_AUD,
  CLAIM_CNF,
  CLAIM_DELEGATE_PAYLOAD,
  CLAIM_IAT,
  CLAIM_NONCE,
  INTERMEDIATE_TYPS,
  isIntermediateTyp,
  isTerminalTyp,
  TERMINAL_TYPS,
  TYP_INTERMEDIATE,
  TYP_TERMINAL,
} from './format.js';
import { ParsedToken, parseToken } from './parse.js';
import {
  isPlainObject,
  type Hasher,
  type JsonObject,
  type JwkVerifierFactory,
  type Verifier,
} from './types.js';

/** A verified token: its signature checked and its disclosures resolved. */
export interface VerifiedToken {
  /** The token, carrying verified state (see {@link ParsedToken.cnfJwk}). */
  token: ParsedToken;
  /** Disclosure-resolved payload, without `_sd` / `_sd_alg`. */
  payload: JsonObject;
  /** Disclosed `delegate_payload` items, empty when the claim is absent. */
  delegateItems: JsonObject[];
}

export interface VerifySdJwtOptions {
  token: string | ParsedToken;
  /** Verifies the signature over the token's `header.payload`. */
  verifier: Verifier;
  hasher: Hasher;
}

/**
 * Verify an SD-JWT signature and resolve its disclosures.
 *
 * This is the only SD-JWT verifier used anywhere in this library; nothing in a
 * delegation chain is validated by a third-party SD-JWT implementation.
 *
 * A token carrying a detached KB-JWT is rejected: this library does not verify
 * one, and accepting the token would leave that JWT silently unchecked. In a
 * dSD-JWT, key binding lives in the terminal KB-SD-JWT instead.
 */
export async function verifySdJwt(options: VerifySdJwtOptions): Promise<VerifiedToken> {
  const token = typeof options.token === 'string' ? parseToken(options.token) : options.token;
  if (token.kbJwt !== null) {
    throw new DelegateSdJwtError(
      'Token carries a detached KB-JWT, which this library does not verify; ' +
        'remove it and verify it separately',
    );
  }
  const ok = await options.verifier(token.signingInput, token.signature);
  if (ok !== true) {
    throw new DelegateSdJwtError('Signature verification failed');
  }
  const payload = await resolveDisclosures(token, options.hasher);
  const delegateItems = await normalizeDelegatePayload(payload, token, options.hasher);
  return { token: token.withVerifiedPayload(payload, delegateItems), payload, delegateItems };
}

export interface VerifyKbSdJwtOptions {
  token: string | ParsedToken;
  /** The preceding token; must already carry verified state. */
  prevToken: ParsedToken;
  jwkVerifierFactory: JwkVerifierFactory;
  hasher: Hasher;
  /** Checked when provided — the verifier's expected audience. */
  expectedAud?: string | undefined;
  /** Checked when provided — the verifier's expected nonce. */
  expectedNonce?: string | undefined;
  /**
   * Require exactly one disclosed `delegate_payload` element whenever the claim
   * is present. Default `true`; see {@link assertDelegateItemCount}.
   */
  requireSingleDelegateItem?: boolean;
  /**
   * Pin whether this hop must end the chain (draft §6, step 4: the final `typ`
   * must match the credential format).
   *
   * `true` requires a terminal `typ`, `false` requires one that delegates
   * onward, and `undefined` accepts either. Every hop before the last must
   * delegate onward, or nothing could follow it.
   */
  expectTerminal?: boolean | undefined;
}

/**
 * Enforce the disclosed-`delegate_payload` cardinality of draft §6.
 *
 * When `requireSingle` holds and the token carries a `delegate_payload` claim,
 * exactly one element must be disclosed. Rejecting zero matters as much as
 * rejecting many: a tampered disclosure fails its digest and RFC 9901 then
 * *removes* the element, so a zero count is how tampering surfaces.
 *
 * A token with no `delegate_payload` claim at all is unconstrained — an SD-JWT
 * VC used as a chain root has none.
 */
export function assertDelegateItemCount(
  payload: JsonObject,
  delegateItems: readonly JsonObject[],
  requireSingle: boolean,
): void {
  if (!requireSingle || !(CLAIM_DELEGATE_PAYLOAD in payload)) return;
  if (delegateItems.length !== 1) {
    throw new DelegateSdJwtError(
      `Expected exactly 1 disclosed ${CLAIM_DELEGATE_PAYLOAD} element, got ${delegateItems.length}`,
    );
  }
}

/**
 * Verify one KB-SD-JWT hop against the token it delegates.
 *
 * Checks, in order: a known `typ`; the signature under the previous hop's
 * `cnf.jwk`; the disclosures; exactly one matching binding claim; a present
 * `iat`; `aud` / `nonce` when expected values are supplied; and that `cnf` is
 * present for an intermediate hop and absent for a terminal one.
 */
export async function verifyKbSdJwt(options: VerifyKbSdJwtOptions): Promise<VerifiedToken> {
  const token = typeof options.token === 'string' ? parseToken(options.token) : options.token;
  const typ = token.typ;
  if (!isTerminalTyp(typ) && !isIntermediateTyp(typ)) {
    throw new DelegateSdJwtError(
      `Unexpected JWT typ: expected one of ${[...TERMINAL_TYPS, ...INTERMEDIATE_TYPS].join(', ')}, ` +
        `got ${JSON.stringify(typ)}`,
    );
  }
  if (options.expectTerminal === true && !isTerminalTyp(typ)) {
    throw new DelegateSdJwtError(
      `Expected a terminal hop (${TYP_TERMINAL}) but got ${typ}, which delegates onward. ` +
        'A presentation to a verifier must end the chain.',
    );
  }
  if (options.expectTerminal === false && !isIntermediateTyp(typ)) {
    throw new DelegateSdJwtError(
      `Expected a hop that delegates onward (${TYP_INTERMEDIATE}) but got ${typ}, which ends the chain`,
    );
  }

  const prevKey = options.prevToken.cnfJwk();
  if (prevKey === null) {
    throw new DelegateSdJwtError(`Previous token does not provide a ${CLAIM_CNF}.jwk`);
  }

  const verifier = await options.jwkVerifierFactory(prevKey, token.alg);
  const verified = await verifySdJwt({ token, verifier, hasher: options.hasher });

  await verifyBinding(verified.payload, options.prevToken, options.hasher);

  if (verified.payload[CLAIM_IAT] === undefined) {
    throw new DelegateSdJwtError(`KB-SD-JWT missing required '${CLAIM_IAT}' claim`);
  }
  assertExpected(verified.payload, CLAIM_AUD, options.expectedAud);
  assertExpected(verified.payload, CLAIM_NONCE, options.expectedNonce);

  const hasCnf = delegatePayloadHasCnf(verified.payload);
  if (isTerminalTyp(typ) && hasCnf) {
    throw new DelegateSdJwtError(
      `Terminal ${typ} MUST NOT carry a '${CLAIM_CNF}' claim in its delegate payload`,
    );
  }
  if (isIntermediateTyp(typ) && !hasCnf) {
    throw new DelegateSdJwtError(
      `Intermediate ${typ} requires a '${CLAIM_CNF}' claim in its delegate payload`,
    );
  }

  assertDelegateItemCount(
    verified.payload,
    verified.delegateItems,
    options.requireSingleDelegateItem ?? true,
  );

  return verified;
}

function assertExpected(payload: JsonObject, claim: string, expected: string | undefined): void {
  if (expected === undefined) return;
  const actual = payload[claim];
  if (actual !== expected) {
    throw new DelegateSdJwtError(
      `KB-SD-JWT ${claim} mismatch: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

function delegatePayloadHasCnf(payload: JsonObject): boolean {
  const delegatePayload = payload[CLAIM_DELEGATE_PAYLOAD];
  if (!Array.isArray(delegatePayload)) return false;
  return delegatePayload.some((item) => isPlainObject(item) && isPlainObject(item[CLAIM_CNF]));
}
