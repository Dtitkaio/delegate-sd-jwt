/** Parsing and canonicalization of compact SD-JWT / KB-SD-JWT tokens. */
import { decodeBase64UrlToString } from './base64url.js';
import { DelegateSdJwtError } from './errors.js';
import { CLAIM_CNF, CLAIM_DELEGATE_PAYLOAD, DISCLOSURE_SEPARATOR, resolveSdAlg } from './format.js';
import { isPlainObject, type Jwk, type JsonObject } from './types.js';

const COMPACT_JWT_PARTS = 3;

/** A parsed compact SD-JWT, optionally carrying verified state. */
export class ParsedToken {
  /** The issuer- (or previous-hop-) signed JWT in compact form. */
  readonly issuerJwt: string;

  /** Raw base64url disclosure strings, in presentation order. */
  readonly disclosures: readonly string[];

  /** A detached trailing KB-JWT, if the token carried one. */
  readonly kbJwt: string | null;

  /** Decoded JWT header. Not authenticated until the signature is verified. */
  readonly header: JsonObject;

  /** Decoded JWT payload. Not authenticated until the signature is verified. */
  readonly payload: JsonObject;

  /** Disclosure-resolved payload, set once the token has been verified. */
  readonly verifiedPayload: JsonObject | null;

  /** Disclosed `delegate_payload` items, set once the token has been verified. */
  readonly delegateItems: readonly JsonObject[] | null;

  constructor(init: {
    issuerJwt: string;
    disclosures: readonly string[];
    kbJwt: string | null;
    header: JsonObject;
    payload: JsonObject;
    verifiedPayload?: JsonObject | null;
    delegateItems?: readonly JsonObject[] | null;
  }) {
    this.issuerJwt = init.issuerJwt;
    this.disclosures = init.disclosures;
    this.kbJwt = init.kbJwt;
    this.header = init.header;
    this.payload = init.payload;
    this.verifiedPayload = init.verifiedPayload ?? null;
    this.delegateItems = init.delegateItems ?? null;
  }

  /** The `typ` header parameter, or `null` when absent or not a string. */
  get typ(): string | null {
    const typ = this.header['typ'];
    return typeof typ === 'string' ? typ : null;
  }

  /** The JWS `alg` header parameter. Guaranteed to be a usable string. */
  get alg(): string {
    return this.header['alg'] as string;
  }

  /** The validated `_sd_alg` of this token, defaulting to `sha-256`. */
  get sdAlg(): string {
    return resolveSdAlg(this.payload);
  }

  /** The JWS signing input (`header.payload`) of the signed JWT. */
  get signingInput(): string {
    return this.issuerJwt.slice(0, this.issuerJwt.lastIndexOf('.'));
  }

  /** The base64url signature of the signed JWT. */
  get signature(): string {
    return this.issuerJwt.slice(this.issuerJwt.lastIndexOf('.') + 1);
  }

  /** JWT + disclosures + trailing separator, excluding any KB-JWT. */
  get sdJwt(): string {
    if (this.disclosures.length === 0) return this.issuerJwt + DISCLOSURE_SEPARATOR;
    return (
      this.issuerJwt +
      DISCLOSURE_SEPARATOR +
      this.disclosures.join(DISCLOSURE_SEPARATOR) +
      DISCLOSURE_SEPARATOR
    );
  }

  /** {@link sdJwt} plus a detached KB-JWT when present. */
  get canonical(): string {
    return this.kbJwt === null ? this.sdJwt : this.sdJwt + this.kbJwt;
  }

  /** Return a copy carrying verified, disclosure-resolved state. */
  withVerifiedPayload(payload: JsonObject, delegateItems: readonly JsonObject[]): ParsedToken {
    return new ParsedToken({
      issuerJwt: this.issuerJwt,
      disclosures: this.disclosures,
      kbJwt: this.kbJwt,
      header: this.header,
      payload: this.payload,
      verifiedPayload: payload,
      delegateItems,
    });
  }

  /**
   * The `cnf.jwk` that the *next* hop must sign with, resolved from the
   * verified payload. Resolution order: disclosed `delegate_payload` items,
   * then `delegate_payload[].cnf`, then the top-level `cnf`.
   *
   * @throws DelegateSdJwtError if this token has not been verified yet.
   */
  cnfJwk(): Jwk | null {
    if (this.verifiedPayload === null) {
      throw new DelegateSdJwtError('Token has not been verified; cnf.jwk is unavailable');
    }
    const cnf = this.findCnf();
    if (cnf === null) return null;
    const jwk = cnf['jwk'];
    if (!isPlainObject(jwk) || typeof jwk['kty'] !== 'string') {
      throw new DelegateSdJwtError(`Malformed ${CLAIM_CNF}.jwk: missing or invalid 'kty'`);
    }
    return jwk as Jwk;
  }

  private findCnf(): JsonObject | null {
    for (const item of this.delegateItems ?? []) {
      const cnf = item[CLAIM_CNF];
      if (isPlainObject(cnf) && 'jwk' in cnf) return cnf;
    }
    const payload = this.verifiedPayload;
    if (payload === null) return null;
    const delegatePayload = payload[CLAIM_DELEGATE_PAYLOAD];
    if (Array.isArray(delegatePayload)) {
      for (const item of delegatePayload) {
        if (!isPlainObject(item)) continue;
        const cnf = item[CLAIM_CNF];
        if (isPlainObject(cnf) && 'jwk' in cnf) return cnf;
      }
    }
    const cnf = payload[CLAIM_CNF];
    if (isPlainObject(cnf) && 'jwk' in cnf) return cnf;
    return null;
  }
}

/** Decode a compact JWT header or payload segment into a JSON object. */
export function decodeJwtSegment(segment: string, partName: string): JsonObject {
  let decoded: unknown;
  try {
    decoded = JSON.parse(decodeBase64UrlToString(segment));
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    throw new DelegateSdJwtError(`Cannot parse JWT ${partName}: ${message}`, { cause });
  }
  if (!isPlainObject(decoded)) {
    throw new DelegateSdJwtError(`JWT ${partName} must decode to a JSON object`);
  }
  return decoded;
}

/**
 * Parse a compact SD-JWT (`<jwt>~<disclosure>*~[<kb-jwt>]`).
 *
 * Rejects an empty JWT, empty disclosure components, JWTs that are not
 * three-part compact serializations, and headers whose `alg` is missing,
 * non-string, or `none`.
 */
export function parseToken(compact: string): ParsedToken {
  if (typeof compact !== 'string' || compact.length === 0) {
    throw new DelegateSdJwtError('Malformed SD-JWT: empty token');
  }
  if (compact.startsWith(DISCLOSURE_SEPARATOR)) {
    throw new DelegateSdJwtError('Malformed SD-JWT: empty issuer JWT');
  }
  if (!compact.includes(DISCLOSURE_SEPARATOR)) {
    throw new DelegateSdJwtError('Malformed SD-JWT: missing disclosure separator');
  }

  const parts = compact.split(DISCLOSURE_SEPARATOR);
  const issuerJwt = parts[0] as string;
  const disclosures = parts.slice(1, -1);
  if (disclosures.some((disclosure) => disclosure.length === 0)) {
    throw new DelegateSdJwtError('Malformed SD-JWT: empty disclosure component');
  }

  let kbJwt: string | null = null;
  if (!compact.endsWith(DISCLOSURE_SEPARATOR)) {
    kbJwt = parts[parts.length - 1] as string;
    if (kbJwt.split('.').length !== COMPACT_JWT_PARTS) {
      throw new DelegateSdJwtError('Malformed KB-JWT: expected header.payload.signature');
    }
  }

  const jwtParts = issuerJwt.split('.');
  if (jwtParts.length !== COMPACT_JWT_PARTS) {
    throw new DelegateSdJwtError('Malformed SD-JWT: JWT must have header.payload.signature');
  }
  const header = decodeJwtSegment(jwtParts[0] as string, 'header');
  const payload = decodeJwtSegment(jwtParts[1] as string, 'payload');
  assertUsableAlg(header);

  return new ParsedToken({ issuerJwt, disclosures, kbJwt, header, payload });
}

function assertUsableAlg(header: JsonObject): void {
  const alg = header['alg'];
  if (typeof alg !== 'string' || alg.length === 0) {
    throw new DelegateSdJwtError("JWT header 'alg' must be a non-empty string");
  }
  if (alg.toLowerCase() === 'none') {
    throw new DelegateSdJwtError("JWT header 'alg' must not be 'none': unsigned tokens are rejected");
  }
}
