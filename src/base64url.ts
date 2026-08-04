/** Unpadded base64url (RFC 4648 §5) and UTF-8 helpers, without Buffer. */
import { DelegateSdJwtError } from './errors.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const LOOKUP = new Int8Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) {
  LOOKUP[ALPHABET.charCodeAt(i)] = i;
}

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder('utf-8', { fatal: true });

/** Encode bytes as unpadded base64url. */
export function encodeBase64Url(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] as number;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += ALPHABET.charAt(b0 >> 2);
    if (b1 === undefined) {
      out += ALPHABET.charAt((b0 & 0x03) << 4);
      break;
    }
    out += ALPHABET.charAt(((b0 & 0x03) << 4) | (b1 >> 4));
    if (b2 === undefined) {
      out += ALPHABET.charAt((b1 & 0x0f) << 2);
      break;
    }
    out += ALPHABET.charAt(((b1 & 0x0f) << 2) | (b2 >> 6));
    out += ALPHABET.charAt(b2 & 0x3f);
  }
  return out;
}

/**
 * Decode unpadded base64url. Rejects padding, non-alphabet characters,
 * impossible lengths, and non-canonical trailing bits.
 */
export function decodeBase64Url(input: string): Uint8Array {
  if (input.length % 4 === 1) {
    throw new DelegateSdJwtError('Invalid base64url: impossible length');
  }
  const out = new Uint8Array(Math.floor((input.length * 3) / 4));
  let accumulator = 0;
  let bits = 0;
  let offset = 0;
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    const value = code < 128 ? (LOOKUP[code] as number) : -1;
    if (value < 0) {
      throw new DelegateSdJwtError(
        `Invalid base64url: unexpected character ${JSON.stringify(input.charAt(i))}`,
      );
    }
    accumulator = (accumulator << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[offset++] = (accumulator >> bits) & 0xff;
    }
  }
  if (bits > 0 && (accumulator & ((1 << bits) - 1)) !== 0) {
    throw new DelegateSdJwtError('Invalid base64url: non-canonical trailing bits');
  }
  return out.subarray(0, offset);
}

/** Decode unpadded base64url into a UTF-8 string, rejecting invalid UTF-8. */
export function decodeBase64UrlToString(input: string): string {
  try {
    return DECODER.decode(decodeBase64Url(input));
  } catch (cause) {
    if (cause instanceof DelegateSdJwtError) throw cause;
    throw new DelegateSdJwtError('Invalid base64url: not valid UTF-8', { cause });
  }
}

/** Encode a UTF-8 string as unpadded base64url. */
export function encodeStringBase64Url(value: string): string {
  return encodeBase64Url(ENCODER.encode(value));
}

/** UTF-8 encode a string. */
export function utf8Bytes(value: string): Uint8Array {
  return ENCODER.encode(value);
}
