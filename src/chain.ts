/** dSD-JWT chain serialization and verification (draft §6). */
import { contextualize, DelegateSdJwtError } from './errors.js';
import {
  CHAIN_SEPARATOR,
  CLAIM_EXP,
  CLAIM_IAT,
  DEFAULT_CLOCK_SKEW_SECONDS,
  DISCLOSURE_SEPARATOR,
} from './format.js';
import { ParsedToken, parseToken } from './parse.js';
import type { Hasher, JsonObject, JwkVerifierFactory, RootVerifierResolver } from './types.js';
import { assertDelegateItemCount, verifyKbSdJwt, verifySdJwt } from './verify.js';

/**
 * Join tokens into a dSD-JWT.
 *
 * Each token is a compact SD-JWT ending in `~`; the boundary between two
 * tokens is an empty disclosure component, so the result looks like
 * `<jwt>~<disclosure>~~<jwt>~<disclosure>~`.
 */
export function serializeChain(tokens: readonly string[]): string {
  if (tokens.length === 0) {
    throw new DelegateSdJwtError('Cannot serialize an empty chain');
  }
  const parts = tokens.map((token, index) => {
    if (typeof token !== 'string' || token.length === 0) {
      throw new DelegateSdJwtError(`Chain token ${index} is empty`);
    }
    if (!token.endsWith(DISCLOSURE_SEPARATOR)) {
      throw new DelegateSdJwtError(
        `Chain token ${index} must be a compact SD-JWT ending in '${DISCLOSURE_SEPARATOR}'; ` +
          'a detached KB-JWT is not part of a dSD-JWT chain',
      );
    }
    return token.slice(0, -1);
  });
  return parts.join(CHAIN_SEPARATOR) + DISCLOSURE_SEPARATOR;
}

/**
 * Split a dSD-JWT into its tokens, root first.
 *
 * Splitting on `~~` consumes the trailing separator of every token except the
 * last, so it is restored before parsing. The last token keeps its own tail,
 * which is what makes a detached KB-JWT detectable.
 */
export function splitChain(chain: string): ParsedToken[] {
  if (typeof chain !== 'string' || chain.length === 0) {
    throw new DelegateSdJwtError('Cannot split an empty chain');
  }
  const parts = chain.split(CHAIN_SEPARATOR);
  return parts.map((part, index) => {
    const isLast = index === parts.length - 1;
    let compact = part;
    if (!isLast && !part.endsWith(DISCLOSURE_SEPARATOR)) {
      // A token with no disclosures is just `<jwt>` here, with no separator at
      // all — do not mistake its own JWT for a trailing KB-JWT.
      const hasDisclosures = part.includes(DISCLOSURE_SEPARATOR);
      const tail = part.slice(part.lastIndexOf(DISCLOSURE_SEPARATOR) + 1);
      if (hasDisclosures && looksLikeCompactJwt(tail)) {
        throw new DelegateSdJwtError(
          `Chain token ${index} carries a detached KB-JWT; dSD-JWT+KB is not supported`,
        );
      }
      compact = part + DISCLOSURE_SEPARATOR;
    }
    try {
      return parseToken(compact);
    } catch (cause) {
      throw contextualize(`Chain token ${index}`, cause);
    }
  });
}

function looksLikeCompactJwt(value: string): boolean {
  return value.split('.').length === 3;
}

export interface VerifyChainOptions {
  /** A dSD-JWT in compact serialization. */
  chain: string;
  /** Resolves the root SD-JWT's issuer key (from `kid`, `x5c`, a DID, …). */
  rootVerifier: RootVerifierResolver;
  /** Builds a verifier for each hop from the previous hop's `cnf.jwk`. */
  jwkVerifierFactory: JwkVerifierFactory;
  hasher: Hasher;
  /** Tolerance for `exp` / `iat`, in seconds. Default 300. */
  clockSkewSeconds?: number;
  /** Expected audience of the final hop. */
  expectedAud?: string;
  /** Expected nonce of the final hop. */
  expectedNonce?: string;
  /** Seconds since the epoch to evaluate time claims against. Default: now. */
  currentTime?: number;
  /**
   * Allow the *final* hop to disclose more than one `delegate_payload` element.
   * Non-final hops are always limited to exactly one.
   *
   * Default `false`, the verifier's rule: a presentation discloses exactly one
   * element (draft §6). Set it to `true` only when the caller is a delegate
   * receiving a handoff, where several elements may be passed on at once.
   */
  allowMultipleFinalDelegateItems?: boolean;
}

export interface VerifiedChain {
  /**
   * Effective payloads, root first: the disclosed `delegate_payload` items of
   * each token, or the token's own payload when it carries no delegate payload
   * (as with an SD-JWT VC root).
   *
   * Constraint checks over these payloads — amounts, merchants, scopes — are
   * application policy, not this library's concern.
   */
  payloads: JsonObject[];
  /** The verified tokens, root first. */
  tokens: ParsedToken[];
}

/**
 * Verify a dSD-JWT delegation chain back to its issuer.
 *
 * The root is verified with `rootVerifier`; every subsequent hop is verified
 * with the previous hop's `cnf.jwk`, is bound to it by `sd_hash` or
 * `issuer_jwt_hash`, and must carry `iat`. `expectedAud` / `expectedNonce` are
 * enforced on the final hop. Any failure aborts the whole chain.
 */
export async function verifyChain(options: VerifyChainOptions): Promise<VerifiedChain> {
  const tokens = splitChain(options.chain);
  if (tokens.length === 0) {
    throw new DelegateSdJwtError('Chain contains no tokens');
  }
  const detached = tokens.findIndex((token) => token.kbJwt !== null);
  if (detached !== -1) {
    throw new DelegateSdJwtError(
      `Chain token ${detached} carries a detached KB-JWT; dSD-JWT+KB is not supported`,
    );
  }

  const now = options.currentTime ?? Math.floor(Date.now() / 1000);
  const skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
  const payloads: JsonObject[] = [];

  const root = tokens[0] as ParsedToken;
  let verifiedRoot;
  try {
    const rootVerifier = await options.rootVerifier({ header: root.header, payload: root.payload });
    verifiedRoot = await verifySdJwt({
      token: root,
      verifier: rootVerifier,
      hasher: options.hasher,
    });
    assertDelegateItemCount(verifiedRoot.payload, verifiedRoot.delegateItems, true);
  } catch (cause) {
    throw contextualize('Chain token 0', cause);
  }
  tokens[0] = verifiedRoot.token;
  checkTimeClaims([verifiedRoot.payload, ...verifiedRoot.delegateItems], 0, now, skew);
  payloads.push(
    ...(verifiedRoot.delegateItems.length > 0 ? verifiedRoot.delegateItems : [verifiedRoot.payload]),
  );

  for (let i = 1; i < tokens.length; i++) {
    const isLast = i === tokens.length - 1;
    let verified;
    try {
      verified = await verifyKbSdJwt({
        token: tokens[i] as ParsedToken,
        prevToken: tokens[i - 1] as ParsedToken,
        jwkVerifierFactory: options.jwkVerifierFactory,
        hasher: options.hasher,
        expectedAud: isLast ? options.expectedAud : undefined,
        expectedNonce: isLast ? options.expectedNonce : undefined,
        requireSingleDelegateItem: !isLast || !(options.allowMultipleFinalDelegateItems ?? false),
      });
    } catch (cause) {
      throw contextualize(`Chain token ${i}`, cause);
    }
    tokens[i] = verified.token;
    checkTimeClaims([verified.payload, ...verified.delegateItems], i, now, skew);
    payloads.push(...(verified.delegateItems.length > 0 ? verified.delegateItems : [verified.payload]));
  }

  return { payloads, tokens };
}

/** Reject expired payloads, future `iat`, and non-numeric time claims. */
function checkTimeClaims(
  payloads: readonly JsonObject[],
  tokenIndex: number,
  now: number,
  skew: number,
): void {
  for (const payload of payloads) {
    const exp = payload[CLAIM_EXP];
    if (exp !== undefined) {
      if (typeof exp !== 'number' || !Number.isFinite(exp)) {
        throw new DelegateSdJwtError(
          `Chain token ${tokenIndex} has an invalid '${CLAIM_EXP}' claim: ${JSON.stringify(exp)}`,
        );
      }
      if (now > exp + skew) {
        throw new DelegateSdJwtError(`Chain token ${tokenIndex} expired at ${exp}`);
      }
    }
    const iat = payload[CLAIM_IAT];
    if (iat !== undefined) {
      if (typeof iat !== 'number' || !Number.isFinite(iat)) {
        throw new DelegateSdJwtError(
          `Chain token ${tokenIndex} has an invalid '${CLAIM_IAT}' claim: ${JSON.stringify(iat)}`,
        );
      }
      if (iat > now + skew) {
        throw new DelegateSdJwtError(`Chain token ${tokenIndex} '${CLAIM_IAT}' is in the future: ${iat}`);
      }
    }
  }
}
