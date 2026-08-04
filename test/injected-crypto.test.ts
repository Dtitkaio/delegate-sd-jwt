/**
 * The injected-crypto contract: signing happens behind a callback, so a wallet
 * or KMS can hold the private key and this library never sees it. Also covers
 * the delegate-handoff variant of the disclosure-count rule.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  createDisclosure,
  createKbSdJwt,
  computeDisclosureDigest,
  DEFAULT_SD_ALG,
  DelegateSdJwtError,
  decodeBase64Url,
  importEcPrivateKey,
  parseToken,
  serializeChain,
  splitChain,
  verifyChain,
  webcryptoHasher,
  webcryptoJwkVerifier,
  webcryptoSigner,
  type Jwk,
  type JsonObject,
  type JwkVerifierFactory,
  type Signer,
} from '../src/index.js';
import {
  AUD,
  buildFixture,
  generateEcKey,
  hasher,
  issueSdJwtVc,
  NOW,
  PRESENTATION_NONCE,
  rootVerifierFor,
  saltGenerator,
  signJwt,
} from './helpers.js';

/**
 * Stands in for `agent.kms.sign({ keyId, data, algorithm })`: the key lives
 * behind an opaque handle and only the signing input crosses the boundary.
 */
function kmsSigner(kms: { sign(keyId: string, signingInput: string): Promise<string> }, keyId: string): Signer {
  return (signingInput) => kms.sign(keyId, signingInput);
}

test('a chain can be built entirely through an opaque signing service', async () => {
  const issuer = await generateEcKey();
  const holder = await generateEcKey();
  const agent = await generateEcKey();

  // The "KMS" is the only thing holding key material.
  const keyring = new Map<string, CryptoKey>([
    ['issuer-1', issuer.privateKey],
    ['holder-1', holder.privateKey],
    ['agent-1', agent.privateKey],
  ]);
  const calls: string[] = [];
  const kms = {
    async sign(keyId: string, signingInput: string): Promise<string> {
      const key = keyring.get(keyId);
      assert.ok(key, `unknown keyId ${keyId}`);
      calls.push(keyId);
      return webcryptoSigner(key, 'ES256')(signingInput);
    },
  };

  const root = await issueSdJwtVc({
    issuer: { ...issuer, signer: kmsSigner(kms, 'issuer-1') },
    plain: { iss: 'https://issuer.example', vct: 'urn:example:card', cnf: { jwk: holder.publicJwk } },
    disclosed: { cardholder: 'A. Holder' },
  });
  const hop1 = await createKbSdJwt({
    prevToken: root,
    claims: { cnf: { jwk: agent.publicJwk }, scope: 'payment', exp: NOW + 600 },
    aud: AUD,
    nonce: 'agent-nonce',
    alg: 'ES256',
    signer: kmsSigner(kms, 'holder-1'),
    hasher,
    saltGenerator,
    iat: NOW,
  });
  const hop2 = await createKbSdJwt({
    prevToken: hop1,
    claims: { amount: '10.00' },
    aud: AUD,
    nonce: PRESENTATION_NONCE,
    alg: 'ES256',
    signer: kmsSigner(kms, 'agent-1'),
    hasher,
    saltGenerator,
    iat: NOW,
  });

  const { payloads } = await verifyChain({
    chain: serializeChain([root, hop1, hop2]),
    rootVerifier: rootVerifierFor(issuer.publicJwk),
    jwkVerifierFactory: webcryptoJwkVerifier,
    hasher,
    expectedAud: AUD,
    expectedNonce: PRESENTATION_NONCE,
    currentTime: NOW + 60,
  });

  assert.deepEqual(calls, ['issuer-1', 'holder-1', 'agent-1']);
  assert.equal((payloads[2] as JsonObject)['amount'], '10.00');
});

test('the verifier factory receives the cnf.jwk of the preceding hop', async () => {
  const fixture = await buildFixture();
  const seen: Jwk[] = [];
  const recording: JwkVerifierFactory = (jwk, alg) => {
    seen.push(jwk);
    return webcryptoJwkVerifier(jwk, alg);
  };
  await verifyChain({
    chain: fixture.chain,
    rootVerifier: fixture.rootVerifier,
    jwkVerifierFactory: recording,
    hasher,
    expectedAud: AUD,
    expectedNonce: PRESENTATION_NONCE,
    currentTime: NOW + 60,
  });
  assert.deepEqual(seen, [fixture.holder.publicJwk, fixture.agent.publicJwk]);
});

test('a hop handing several delegate payloads on is rejected by default and allowed opt-in', async () => {
  const fixture = await buildFixture();
  const hop2 = splitChain(fixture.chain)[2]!;

  const first = createDisclosure({ amount: '1.00' }, saltGenerator);
  const second = createDisclosure({ amount: '2.00' }, saltGenerator);
  const payload: JsonObject = {
    ...hop2.payload,
    delegate_payload: [
      { '...': await computeDisclosureDigest(first, DEFAULT_SD_ALG, hasher) },
      { '...': await computeDisclosureDigest(second, DEFAULT_SD_ALG, hasher) },
    ],
  };
  const jwt = await signJwt(
    { alg: fixture.agent.alg, typ: hop2.typ },
    payload,
    fixture.agent.signer,
  );
  const multi = [jwt, first, second].join('~') + '~';

  const options = {
    chain: serializeChain([fixture.root, fixture.hop1, multi]),
    rootVerifier: fixture.rootVerifier,
    jwkVerifierFactory: webcryptoJwkVerifier,
    hasher: webcryptoHasher,
    expectedAud: AUD,
    expectedNonce: PRESENTATION_NONCE,
    currentTime: NOW + 60,
  };

  await assert.rejects(
    verifyChain(options),
    (error: Error) =>
      error instanceof DelegateSdJwtError &&
      /Expected exactly 1 disclosed delegate_payload element, got 2/.test(error.message),
  );

  const { payloads } = await verifyChain({ ...options, allowMultipleFinalDelegateItems: true });
  assert.equal(payloads.length, 4);
});

test('a non-final hop may never disclose more than one delegate payload', async () => {
  const fixture = await buildFixture();
  const hop1 = splitChain(fixture.chain)[1]!;
  const first = createDisclosure({ cnf: { jwk: fixture.agent.publicJwk } }, saltGenerator);
  const second = createDisclosure({ extra: true }, saltGenerator);
  const payload: JsonObject = {
    ...hop1.payload,
    delegate_payload: [
      { '...': await computeDisclosureDigest(first, DEFAULT_SD_ALG, hasher) },
      { '...': await computeDisclosureDigest(second, DEFAULT_SD_ALG, hasher) },
    ],
  };
  const jwt = await signJwt({ alg: fixture.holder.alg, typ: hop1.typ }, payload, fixture.holder.signer);
  await assert.rejects(
    verifyChain({
      chain: serializeChain([fixture.root, [jwt, first, second].join('~') + '~', fixture.hop2]),
      rootVerifier: fixture.rootVerifier,
      jwkVerifierFactory: webcryptoJwkVerifier,
      hasher,
      currentTime: NOW + 60,
      allowMultipleFinalDelegateItems: true,
    }),
    (error: Error) =>
      error instanceof DelegateSdJwtError && /Expected exactly 1 disclosed/.test(error.message),
  );
});

test('ES384 keys work end to end', async () => {
  const issuer = await generateEcKey('ES384');
  const holder = await generateEcKey('ES384');
  const root = await issueSdJwtVc({
    issuer,
    plain: { iss: 'https://issuer.example', vct: 'urn:example:vct', cnf: { jwk: holder.publicJwk } },
    disclosed: { given_name: 'Ada' },
  });
  const hop = await createKbSdJwt({
    prevToken: root,
    claims: { purpose: 'age check' },
    aud: AUD,
    nonce: PRESENTATION_NONCE,
    alg: 'ES384',
    signer: holder.signer,
    hasher,
    saltGenerator,
    iat: NOW,
  });
  const { payloads } = await verifyChain({
    chain: serializeChain([root, hop]),
    rootVerifier: rootVerifierFor(issuer.publicJwk, 'ES384'),
    jwkVerifierFactory: webcryptoJwkVerifier,
    hasher,
    expectedAud: AUD,
    expectedNonce: PRESENTATION_NONCE,
    currentTime: NOW + 60,
  });
  assert.equal(payloads.length, 2);
});

test('importEcPrivateKey round-trips a private JWK into a usable signer', async () => {
  const key = await generateEcKey();
  const imported = await importEcPrivateKey(key.privateJwk, 'ES256');
  const signer = webcryptoSigner(imported, 'ES256');
  const signature = await signer('header.payload');
  const verifier = await webcryptoJwkVerifier(key.publicJwk, 'ES256');
  assert.equal(await verifier('header.payload', signature), true);
  assert.equal(await verifier('header.tampered', signature), false);
});

test('importEcPrivateKey rejects a mismatched curve and a public-only JWK', async () => {
  const key = await generateEcKey();
  await assert.rejects(
    importEcPrivateKey(key.privateJwk, 'ES384'),
    (error: Error) => error instanceof DelegateSdJwtError && /does not match ES384/.test(error.message),
  );
  await assert.rejects(
    importEcPrivateKey(key.publicJwk, 'ES256'),
    (error: Error) => error instanceof DelegateSdJwtError && /missing 'd'/.test(error.message),
  );
});

test('a verifier that rejects a garbage signature does not throw', async () => {
  const key = await generateEcKey();
  const verifier = await webcryptoJwkVerifier(key.publicJwk, 'ES256');
  assert.equal(await verifier('header.payload', 'not-a-signature'), false);
  assert.equal(await verifier('header.payload', 'not base64url!!'), false);
});

test('base64url decoding rejects padding, stray characters, and bad lengths', () => {
  assert.throws(() => decodeBase64Url('YWJj='), DelegateSdJwtError);
  assert.throws(() => decodeBase64Url('ab+c'), DelegateSdJwtError);
  assert.throws(() => decodeBase64Url('a'), DelegateSdJwtError);
  assert.deepEqual([...decodeBase64Url('YWJj')], [0x61, 0x62, 0x63]);
});

test('parseToken rejects structurally broken tokens', () => {
  for (const broken of ['', '~abc~', 'header.payload', 'a.b.c', 'a.b.c~~d~']) {
    assert.throws(() => parseToken(broken), DelegateSdJwtError, `must reject ${JSON.stringify(broken)}`);
  }
});
