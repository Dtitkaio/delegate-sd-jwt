/**
 * Strict RFC 9901 §7.1 disclosure processing.
 *
 * This resolver is deliberately unforgiving. It rejects malformed disclosures,
 * duplicate digests, digests referenced more than once, `_sd` arrays that are
 * not arrays of strings, and disclosed claim names that collide with an
 * existing claim or with a reserved key.
 */
import { decodeBase64UrlToString } from './base64url.js';
import { computeDisclosureDigest } from './binding.js';
import { DelegateSdJwtError } from './errors.js';
import {
  CLAIM_ARRAY_DISCLOSURE,
  CLAIM_DELEGATE_PAYLOAD,
  CLAIM_SD,
  CLAIM_SD_ALG,
} from './format.js';
import type { ParsedToken } from './parse.js';
import { isPlainObject, type Hasher, type JsonObject } from './types.js';

const ARRAY_DISCLOSURE_LENGTH = 2;
const PROPERTY_DISCLOSURE_LENGTH = 3;

interface Disclosure {
  /** `array` for `[salt, value]`, `property` for `[salt, name, value]`. */
  readonly kind: 'array' | 'property';
  readonly name: string | null;
  readonly value: unknown;
}

/** Decode one raw disclosure string, enforcing RFC 9901 §4.2 structure. */
function decodeDisclosure(raw: string): Disclosure {
  let parsed: unknown;
  try {
    parsed = JSON.parse(decodeBase64UrlToString(raw));
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    throw new DelegateSdJwtError(`Malformed disclosure: ${message}`, { cause });
  }
  if (!Array.isArray(parsed)) {
    throw new DelegateSdJwtError('Malformed disclosure: must be a JSON array');
  }
  if (typeof parsed[0] !== 'string') {
    throw new DelegateSdJwtError('Malformed disclosure: salt must be a string');
  }
  if (parsed.length === ARRAY_DISCLOSURE_LENGTH) {
    return { kind: 'array', name: null, value: parsed[1] };
  }
  if (parsed.length === PROPERTY_DISCLOSURE_LENGTH) {
    const name = parsed[1];
    if (typeof name !== 'string') {
      throw new DelegateSdJwtError('Malformed disclosure: claim name must be a string');
    }
    if (name === CLAIM_SD || name === CLAIM_ARRAY_DISCLOSURE) {
      throw new DelegateSdJwtError(`Malformed disclosure: claim name must not be '${name}'`);
    }
    return { kind: 'property', name, value: parsed[2] };
  }
  throw new DelegateSdJwtError(
    'Malformed disclosure: must be [salt, value] or [salt, name, value]',
  );
}

async function buildDisclosureMap(
  disclosures: readonly string[],
  sdAlg: string,
  hasher: Hasher,
): Promise<Map<string, Disclosure>> {
  const byDigest = new Map<string, Disclosure>();
  for (const raw of disclosures) {
    const disclosure = decodeDisclosure(raw);
    const digest = await computeDisclosureDigest(raw, sdAlg, hasher);
    if (byDigest.has(digest)) {
      throw new DelegateSdJwtError(`Duplicate disclosure digest: ${digest}`);
    }
    byDigest.set(digest, disclosure);
  }
  return byDigest;
}

function takeDisclosure(
  digest: string,
  byDigest: Map<string, Disclosure>,
  used: Set<string>,
): Disclosure | undefined {
  const disclosure = byDigest.get(digest);
  if (disclosure === undefined) return undefined;
  if (used.has(digest)) {
    throw new DelegateSdJwtError(`Disclosure digest referenced more than once: ${digest}`);
  }
  used.add(digest);
  return disclosure;
}

/** Read an array element of the form `{"...": "<digest>"}`. */
function arrayDisclosureRef(element: unknown): string | null {
  if (!isPlainObject(element)) return null;
  const keys = Object.keys(element);
  if (keys.length !== 1 || keys[0] !== CLAIM_ARRAY_DISCLOSURE) return null;
  const digest = element[CLAIM_ARRAY_DISCLOSURE];
  if (typeof digest !== 'string') {
    throw new DelegateSdJwtError(`'${CLAIM_ARRAY_DISCLOSURE}' value must be a digest string`);
  }
  return digest;
}

function resolveValue(
  value: unknown,
  byDigest: Map<string, Disclosure>,
  used: Set<string>,
): unknown {
  if (Array.isArray(value)) return resolveArray(value, byDigest, used);
  if (isPlainObject(value)) return resolveObject(value, byDigest, used);
  return value;
}

function resolveArray(
  array: readonly unknown[],
  byDigest: Map<string, Disclosure>,
  used: Set<string>,
): unknown[] {
  const out: unknown[] = [];
  for (const element of array) {
    const digest = arrayDisclosureRef(element);
    if (digest === null) {
      out.push(resolveValue(element, byDigest, used));
      continue;
    }
    const disclosure = takeDisclosure(digest, byDigest, used);
    // An undisclosed element is removed entirely (RFC 9901 §7.1).
    if (disclosure === undefined) continue;
    if (disclosure.kind !== 'array') {
      throw new DelegateSdJwtError(
        'Array-element disclosure must be [salt, value], got [salt, name, value]',
      );
    }
    out.push(resolveValue(disclosure.value, byDigest, used));
  }
  return out;
}

function resolveObject(
  object: JsonObject,
  byDigest: Map<string, Disclosure>,
  used: Set<string>,
): JsonObject {
  const out: JsonObject = {};
  for (const [key, value] of Object.entries(object)) {
    if (key === CLAIM_SD) continue;
    if (key === CLAIM_ARRAY_DISCLOSURE) {
      throw new DelegateSdJwtError(
        `'${CLAIM_ARRAY_DISCLOSURE}' is only valid as an array-element disclosure reference`,
      );
    }
    out[key] = resolveValue(value, byDigest, used);
  }

  const sd = object[CLAIM_SD];
  if (sd === undefined) return out;
  if (!Array.isArray(sd) || sd.some((digest) => typeof digest !== 'string')) {
    throw new DelegateSdJwtError(`'${CLAIM_SD}' must be an array of digest strings`);
  }
  for (const digest of sd as readonly string[]) {
    const disclosure = takeDisclosure(digest, byDigest, used);
    // Unknown digests are undisclosed claims or decoys; both are skipped.
    if (disclosure === undefined) continue;
    if (disclosure.kind !== 'property' || disclosure.name === null) {
      throw new DelegateSdJwtError(
        'Object-property disclosure must be [salt, name, value], got [salt, value]',
      );
    }
    const name = disclosure.name;
    if (Object.prototype.hasOwnProperty.call(out, name)) {
      throw new DelegateSdJwtError(`Disclosed claim '${name}' collides with an existing claim`);
    }
    out[name] = resolveValue(disclosure.value, byDigest, used);
  }
  return out;
}

/**
 * Resolve every disclosure of `token` into its payload.
 *
 * `_sd` and `_sd_alg` are removed from the returned payload; the raw values
 * remain available on {@link ParsedToken.payload} and {@link ParsedToken.sdAlg}.
 */
export async function resolveDisclosures(
  token: ParsedToken,
  hasher: Hasher,
): Promise<JsonObject> {
  const byDigest = await buildDisclosureMap(token.disclosures, token.sdAlg, hasher);
  const payload = resolveObject(token.payload, byDigest, new Set<string>());
  delete payload[CLAIM_SD_ALG];
  return payload;
}

/**
 * Normalize `delegate_payload` in place and return its disclosed object items.
 *
 * Items are normally objects once disclosures are resolved. For CMWallet
 * interoperability a string item is also accepted: it is treated as a digest
 * referencing one of the token's appended disclosures, or failing that as a
 * raw disclosure string. Either way the value is authenticated — by digest
 * against a disclosure, or by the signature over the payload that carries it.
 */
export async function normalizeDelegatePayload(
  payload: JsonObject,
  token: ParsedToken,
  hasher: Hasher,
): Promise<JsonObject[]> {
  const delegatePayload = payload[CLAIM_DELEGATE_PAYLOAD];
  if (!Array.isArray(delegatePayload)) return [];

  const normalized: unknown[] = [];
  const items: JsonObject[] = [];
  for (const item of delegatePayload) {
    if (isPlainObject(item)) {
      normalized.push(item);
      items.push(item);
      continue;
    }
    if (typeof item === 'string') {
      const resolved = await resolveStringItem(item, token, hasher);
      if (resolved !== null) {
        normalized.push(resolved);
        items.push(resolved);
        continue;
      }
    }
    normalized.push(item);
  }
  payload[CLAIM_DELEGATE_PAYLOAD] = normalized;
  return items;
}

async function resolveStringItem(
  item: string,
  token: ParsedToken,
  hasher: Hasher,
): Promise<JsonObject | null> {
  for (const raw of token.disclosures) {
    if ((await computeDisclosureDigest(raw, token.sdAlg, hasher)) !== item) continue;
    const value = decodeDisclosure(raw).value;
    return isPlainObject(value) ? value : null;
  }
  try {
    const value = decodeDisclosure(item).value;
    return isPlainObject(value) ? value : null;
  } catch {
    return null;
  }
}
