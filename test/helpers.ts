/** Test fixtures: EC keys, an SD-JWT VC issuer, and a three-hop chain. */
import {
  computeDisclosureDigest,
  createDisclosure,
  createKbSdJwt,
  DEFAULT_SD_ALG,
  DISCLOSURE_SEPARATOR,
  encodeStringBase64Url,
  serializeChain,
  webcryptoHasher,
  webcryptoJwkVerifier,
  webcryptoSaltGenerator,
  webcryptoSigner,
  type Jwk,
  type JsonObject,
  type RootVerifierResolver,
  type Signer,
} from '../src/index.js';

export const hasher = webcryptoHasher;
export const saltGenerator = webcryptoSaltGenerator;

/** A fixed "now" so tests never depend on the wall clock. */
export const NOW = 1_800_000_000;

export const AUD = 'https://merchant.example';
export const DELEGATION_NONCE = 'nonce-for-the-agent';
export const PRESENTATION_NONCE = 'nonce-from-the-verifier';

const CURVE_BY_ALG: Record<string, string> = {
  ES256: 'P-256',
  ES384: 'P-384',
  ES512: 'P-521',
};

export interface TestKey {
  alg: string;
  privateKey: CryptoKey;
  privateJwk: Jwk;
  publicJwk: Jwk;
  signer: Signer;
}

export async function generateEcKey(alg = 'ES256'): Promise<TestKey> {
  const namedCurve = CURVE_BY_ALG[alg] as string;
  const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const priv = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return {
    alg,
    privateKey: pair.privateKey,
    privateJwk: { kty: 'EC', crv: priv.crv, x: priv.x, y: priv.y, d: priv.d } as Jwk,
    publicJwk: { kty: 'EC', crv: pub.crv, x: pub.x, y: pub.y } as Jwk,
    signer: webcryptoSigner(pair.privateKey, alg),
  };
}

/** A root verifier that always returns the given public key. */
export function rootVerifierFor(key: Jwk, alg = 'ES256'): RootVerifierResolver {
  return () => webcryptoJwkVerifier(key, alg);
}

/** Sign a compact JWT from a header and payload. */
export async function signJwt(
  header: JsonObject,
  payload: JsonObject,
  signer: Signer,
): Promise<string> {
  const signingInput = `${encodeStringBase64Url(JSON.stringify(header))}.${encodeStringBase64Url(
    JSON.stringify(payload),
  )}`;
  return `${signingInput}.${await signer(signingInput)}`;
}

/**
 * Issue an SD-JWT VC of the shape a wallet already holds: `typ: dc+sd-jwt`,
 * plain `vct` / `iss` / `cnf` claims, and object-property disclosures in `_sd`.
 * No `delegate_payload` — this is the "any RFC 9901 SD-JWT is a valid root" case.
 */
export async function issueSdJwtVc(options: {
  issuer: TestKey;
  plain: JsonObject;
  disclosed: JsonObject;
  header?: JsonObject;
}): Promise<string> {
  const disclosures: string[] = [];
  const digests: string[] = [];
  for (const [name, value] of Object.entries(options.disclosed)) {
    const disclosure = createDisclosure(value, saltGenerator, name);
    disclosures.push(disclosure);
    digests.push(await computeDisclosureDigest(disclosure, DEFAULT_SD_ALG, hasher));
  }
  const payload: JsonObject = { _sd_alg: DEFAULT_SD_ALG, ...options.plain, _sd: digests };
  const header: JsonObject = {
    alg: options.issuer.alg,
    typ: 'dc+sd-jwt',
    kid: 'issuer-key-1',
    ...options.header,
  };
  const jwt = await signJwt(header, payload, options.issuer.signer);
  return [jwt, ...disclosures].join(DISCLOSURE_SEPARATOR) + DISCLOSURE_SEPARATOR;
}

export interface Fixture {
  issuer: TestKey;
  /** The user's wallet key, named by the root credential's `cnf`. */
  holder: TestKey;
  /** The AI agent's key, named by the intermediate hop's `cnf`. */
  agent: TestKey;
  root: string;
  hop1: string;
  hop2: string;
  chain: string;
  rootVerifier: RootVerifierResolver;
}

/**
 * Build a full user → agent → merchant chain:
 *   root SD-JWT VC  →  intermediate hop (delegates to the agent)  →  terminal hop.
 */
export async function buildFixture(
  overrides: {
    hop1Claims?: JsonObject;
    hop2Claims?: JsonObject;
    hop1HashMode?: 'sd_hash' | 'issuer_jwt_hash';
    hop2HashMode?: 'sd_hash' | 'issuer_jwt_hash';
    presentationNonce?: string;
    /** Reuse keys across fixtures, e.g. to model one wallet holding two credentials. */
    keys?: { issuer?: TestKey; holder?: TestKey; agent?: TestKey };
  } = {},
): Promise<Fixture> {
  const issuer = overrides.keys?.issuer ?? (await generateEcKey());
  const holder = overrides.keys?.holder ?? (await generateEcKey());
  const agent = overrides.keys?.agent ?? (await generateEcKey());

  const root = await issueSdJwtVc({
    issuer,
    plain: {
      iss: 'https://issuer.example',
      vct: 'https://credentials.example/payment-card',
      iat: NOW - 86_400,
      cnf: { jwk: holder.publicJwk },
    },
    disclosed: { cardholder: 'A. Holder', card_number: '4111111111111111' },
  });

  const hop1 = await createKbSdJwt({
    prevToken: root,
    claims: {
      cnf: { jwk: agent.publicJwk },
      scope: 'payment',
      max_amount: '50.00',
      currency: 'USD',
      exp: NOW + 3600,
      ...overrides.hop1Claims,
    },
    aud: AUD,
    nonce: DELEGATION_NONCE,
    alg: holder.alg,
    signer: holder.signer,
    hasher,
    saltGenerator,
    iat: NOW,
    ...(overrides.hop1HashMode ? { hashMode: overrides.hop1HashMode } : {}),
  });

  const hop2 = await createKbSdJwt({
    prevToken: hop1,
    claims: {
      amount: '42.00',
      currency: 'USD',
      merchant: 'shoes.example',
      ...overrides.hop2Claims,
    },
    aud: AUD,
    nonce: overrides.presentationNonce ?? PRESENTATION_NONCE,
    alg: agent.alg,
    signer: agent.signer,
    hasher,
    saltGenerator,
    iat: NOW,
    ...(overrides.hop2HashMode ? { hashMode: overrides.hop2HashMode } : {}),
  });

  return {
    issuer,
    holder,
    agent,
    root,
    hop1,
    hop2,
    chain: serializeChain([root, hop1, hop2]),
    rootVerifier: rootVerifierFor(issuer.publicJwk),
  };
}
