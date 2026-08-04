/**
 * Default WebCrypto backend, for EC keys only (ES256 / ES384 / ES512).
 *
 * Every function here is optional: the library takes hashing, signing, and
 * verification as parameters. Wallets should inject their own {@link Signer}
 * so private keys never leave the wallet, and DID-based deployments that use
 * Ed25519 should inject a {@link JwkVerifierFactory} built on an EdDSA library
 * — WebCrypto's Ed25519 support is not portable enough to rely on here.
 */
import { decodeBase64Url, encodeBase64Url, utf8Bytes } from './base64url.js';
import { DelegateSdJwtError } from './errors.js';
import type { Hasher, Jwk, JwkVerifierFactory, SaltGenerator, Signer, Verifier } from './types.js';

const SUBTLE_HASH_BY_SD_ALG: Readonly<Record<string, string>> = {
  'sha-256': 'SHA-256',
  'sha-384': 'SHA-384',
  'sha-512': 'SHA-512',
};

interface EcParams {
  namedCurve: string;
  hash: string;
}

const EC_PARAMS_BY_ALG: Readonly<Record<string, EcParams>> = {
  ES256: { namedCurve: 'P-256', hash: 'SHA-256' },
  ES384: { namedCurve: 'P-384', hash: 'SHA-384' },
  ES512: { namedCurve: 'P-521', hash: 'SHA-512' },
};

/**
 * TypeScript 5.7 types `Uint8Array` as `Uint8Array<ArrayBufferLike>`, which is
 * not assignable to `BufferSource` even though every WebCrypto implementation
 * accepts it. The cast is confined to this backend.
 */
function asBufferSource(view: Uint8Array): BufferSource {
  return view as unknown as BufferSource;
}

function ecParams(alg: string): EcParams {
  const params = EC_PARAMS_BY_ALG[alg];
  if (params === undefined) {
    throw new DelegateSdJwtError(
      `Unsupported JWS alg for the WebCrypto backend: ${JSON.stringify(alg)} ` +
        `(supported: ${Object.keys(EC_PARAMS_BY_ALG).join(', ')})`,
    );
  }
  return params;
}

/** {@link Hasher} over WebCrypto digests. */
export const webcryptoHasher: Hasher = async (data, alg) => {
  const name = SUBTLE_HASH_BY_SD_ALG[alg];
  if (name === undefined) {
    throw new DelegateSdJwtError(`Unsupported hash algorithm: ${JSON.stringify(alg)}`);
  }
  const digest = await crypto.subtle.digest(name, asBufferSource(utf8Bytes(data)));
  return new Uint8Array(digest);
};

/** {@link SaltGenerator} over `crypto.getRandomValues`. */
export const webcryptoSaltGenerator: SaltGenerator = (byteLength) =>
  crypto.getRandomValues(new Uint8Array(byteLength));

/** Build a {@link Signer} from an ECDSA private `CryptoKey`. */
export function webcryptoSigner(key: CryptoKey, alg: string): Signer {
  const params = ecParams(alg);
  return async (signingInput) => {
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: params.hash },
      key,
      asBufferSource(utf8Bytes(signingInput)),
    );
    return encodeBase64Url(new Uint8Array(signature));
  };
}

/** {@link JwkVerifierFactory} for EC public JWKs. */
export const webcryptoJwkVerifier: JwkVerifierFactory = async (jwk, alg): Promise<Verifier> => {
  const params = ecParams(alg);
  const key = await crypto.subtle.importKey(
    'jwk',
    toPublicEcJwk(jwk, params.namedCurve),
    { name: 'ECDSA', namedCurve: params.namedCurve },
    false,
    ['verify'],
  );
  return async (signingInput, signatureB64Url) => {
    let signature: Uint8Array;
    try {
      signature = decodeBase64Url(signatureB64Url);
    } catch {
      return false;
    }
    return crypto.subtle.verify(
      { name: 'ECDSA', hash: params.hash },
      key,
      asBufferSource(signature),
      asBufferSource(utf8Bytes(signingInput)),
    );
  };
};

/** Import an EC private JWK as a signing `CryptoKey`. */
export async function importEcPrivateKey(jwk: Jwk, alg: string): Promise<CryptoKey> {
  const params = ecParams(alg);
  const { crv, x, y, d } = jwk;
  if (jwk.kty !== 'EC' || typeof crv !== 'string' || typeof x !== 'string' || typeof y !== 'string') {
    throw new DelegateSdJwtError("Expected an EC JWK with 'crv', 'x', and 'y'");
  }
  if (typeof d !== 'string') {
    throw new DelegateSdJwtError("EC private JWK is missing 'd'");
  }
  if (crv !== params.namedCurve) {
    throw new DelegateSdJwtError(`JWK curve ${crv} does not match ${alg} (expected ${params.namedCurve})`);
  }
  return crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv, x, y, d },
    { name: 'ECDSA', namedCurve: params.namedCurve },
    false,
    ['sign'],
  );
}

function toPublicEcJwk(jwk: Jwk, expectedCurve: string): JsonWebKey {
  const { crv, x, y } = jwk;
  if (jwk.kty !== 'EC' || typeof crv !== 'string' || typeof x !== 'string' || typeof y !== 'string') {
    throw new DelegateSdJwtError("Expected an EC JWK with 'crv', 'x', and 'y'");
  }
  if (crv !== expectedCurve) {
    throw new DelegateSdJwtError(`JWK curve ${crv} does not match the expected ${expectedCurve}`);
  }
  return { kty: 'EC', crv, x, y };
}
