/** End-to-end delegation-chain behaviour. */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  createKbSdJwt,
  createRootSdJwt,
  DelegateSdJwtError,
  serializeChain,
  splitChain,
  verifyChain,
  webcryptoJwkVerifier as jwkVerifierFactory,
  type JsonObject,
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
} from './helpers.js';

const baseOptions = {
  jwkVerifierFactory,
  hasher,
  expectedAud: AUD,
  expectedNonce: PRESENTATION_NONCE,
  currentTime: NOW + 60,
};

test('verifies a user → agent → merchant chain back to the issuer', async () => {
  const fixture = await buildFixture();
  const { payloads, tokens } = await verifyChain({
    chain: fixture.chain,
    rootVerifier: fixture.rootVerifier,
    ...baseOptions,
  });

  assert.equal(tokens.length, 3);
  assert.equal(payloads.length, 3);

  // The root SD-JWT VC has no delegate_payload, so its own resolved payload is
  // returned, disclosures inlined.
  const root = payloads[0] as JsonObject;
  assert.equal(root['vct'], 'https://credentials.example/payment-card');
  assert.equal(root['cardholder'], 'A. Holder');
  assert.equal(root['card_number'], '4111111111111111');
  assert.equal(root['_sd'], undefined, '_sd must be stripped from the resolved payload');
  assert.equal(root['_sd_alg'], undefined, '_sd_alg must be stripped from the resolved payload');

  // The user's grant to the agent.
  const grant = payloads[1] as JsonObject;
  assert.equal(grant['scope'], 'payment');
  assert.equal(grant['max_amount'], '50.00');
  assert.ok(grant['cnf'], 'an intermediate hop names the next key');

  // The agent's presentation to the merchant.
  const presentation = payloads[2] as JsonObject;
  assert.equal(presentation['amount'], '42.00');
  assert.equal(presentation['merchant'], 'shoes.example');
  assert.equal(presentation['cnf'], undefined, 'a terminal hop must not delegate onward');
});

test('a chain round-trips through serialize/split', async () => {
  const fixture = await buildFixture();
  const parts = [fixture.root, fixture.hop1, fixture.hop2];
  const tokens = splitChain(serializeChain(parts));
  assert.equal(tokens.length, 3);
  assert.deepEqual(
    tokens.map((token) => token.sdJwt),
    parts,
  );
  assert.equal(tokens[1]?.typ, 'kb+sd-jwt+kb');
  assert.equal(tokens[2]?.typ, 'kb+sd-jwt');
});

test('rejects a mismatched nonce on the final hop', async () => {
  const fixture = await buildFixture({ presentationNonce: 'attacker-chosen-nonce' });
  await assert.rejects(
    verifyChain({ chain: fixture.chain, rootVerifier: fixture.rootVerifier, ...baseOptions }),
    (error: Error) => error instanceof DelegateSdJwtError && /nonce mismatch/.test(error.message),
  );
});

test('rejects a mismatched audience on the final hop', async () => {
  const fixture = await buildFixture();
  await assert.rejects(
    verifyChain({
      chain: fixture.chain,
      rootVerifier: fixture.rootVerifier,
      ...baseOptions,
      expectedAud: 'https://other-merchant.example',
    }),
    (error: Error) => error instanceof DelegateSdJwtError && /aud mismatch/.test(error.message),
  );
});

test('rejects a root signed by the wrong issuer key', async () => {
  const fixture = await buildFixture();
  const impostor = await generateEcKey();
  await assert.rejects(
    verifyChain({
      chain: fixture.chain,
      rootVerifier: rootVerifierFor(impostor.publicJwk),
      ...baseOptions,
    }),
    (error: Error) =>
      error instanceof DelegateSdJwtError && /Signature verification failed/.test(error.message),
  );
});

test('rejects a hop signed by a key the previous hop did not name', async () => {
  const fixture = await buildFixture();
  const rogue = await generateEcKey();
  // The rogue agent re-signs the terminal hop with its own key.
  const forged = await createKbSdJwt({
    prevToken: fixture.hop1,
    claims: { amount: '9999.00', merchant: 'attacker.example' },
    aud: AUD,
    nonce: PRESENTATION_NONCE,
    alg: rogue.alg,
    signer: rogue.signer,
    hasher,
    saltGenerator,
    iat: NOW,
  });
  await assert.rejects(
    verifyChain({
      chain: serializeChain([fixture.root, fixture.hop1, forged]),
      rootVerifier: fixture.rootVerifier,
      ...baseOptions,
    }),
    (error: Error) =>
      error instanceof DelegateSdJwtError && /Signature verification failed/.test(error.message),
  );
});

test('rejects a tampered root disclosure', async () => {
  const fixture = await buildFixture();
  const tokens = splitChain(fixture.chain);
  const root = tokens[0]!;
  // Re-encode the cardholder disclosure with a different value. The digest no
  // longer matches _sd, and the hop's sd_hash no longer matches the root.
  const tampered =
    root.issuerJwt +
    '~' +
    root.disclosures
      .map((disclosure, index) => (index === 0 ? forgeDisclosure(disclosure) : disclosure))
      .join('~') +
    '~';
  await assert.rejects(
    verifyChain({
      chain: serializeChain([tampered, fixture.hop1, fixture.hop2]),
      rootVerifier: fixture.rootVerifier,
      ...baseOptions,
    }),
    (error: Error) => error instanceof DelegateSdJwtError && /sd_hash mismatch/.test(error.message),
  );
});

test('rejects a tampered delegate payload on the final hop', async () => {
  const fixture = await buildFixture();
  const tokens = splitChain(fixture.chain);
  const hop2 = tokens[2]!;
  const tampered = hop2.issuerJwt + '~' + forgeDisclosure(hop2.disclosures[0]!) + '~';
  await assert.rejects(
    verifyChain({
      chain: serializeChain([fixture.root, fixture.hop1, tampered]),
      rootVerifier: fixture.rootVerifier,
      ...baseOptions,
    }),
    (error: Error) =>
      error instanceof DelegateSdJwtError &&
      /Expected exactly 1 disclosed delegate_payload element, got 0/.test(error.message),
  );
});

test('rejects an expired delegate payload', async () => {
  const fixture = await buildFixture({ hop1Claims: { exp: NOW - 3600 } });
  await assert.rejects(
    verifyChain({ chain: fixture.chain, rootVerifier: fixture.rootVerifier, ...baseOptions }),
    (error: Error) => error instanceof DelegateSdJwtError && /expired at/.test(error.message),
  );
});

test('accepts an expired delegate payload inside the clock skew', async () => {
  const fixture = await buildFixture({ hop1Claims: { exp: NOW - 60 } });
  const { payloads } = await verifyChain({
    chain: fixture.chain,
    rootVerifier: fixture.rootVerifier,
    ...baseOptions,
    clockSkewSeconds: 300,
  });
  assert.equal(payloads.length, 3);
});

test('rejects an iat in the future', async () => {
  const fixture = await buildFixture();
  await assert.rejects(
    verifyChain({
      chain: fixture.chain,
      rootVerifier: fixture.rootVerifier,
      ...baseOptions,
      currentTime: NOW - 10_000,
    }),
    (error: Error) => error instanceof DelegateSdJwtError && /in the future/.test(error.message),
  );
});

test('rejects a chain spliced from two chains that share a holder key', async () => {
  // Mix-and-match (draft §8.1): one wallet key holds two credentials, and the
  // agent swaps in the more permissive grant. Every signature is genuine — only
  // the sd_hash binding catches it, which is why it is checked in both
  // directions.
  const keys = {
    issuer: await generateEcKey(),
    holder: await generateEcKey(),
    agent: await generateEcKey(),
  };
  const restricted = await buildFixture({ keys, hop1Claims: { max_amount: '5.00' } });
  const permissive = await buildFixture({ keys, hop1Claims: { max_amount: '5000.00' } });

  // Control: each chain is valid on its own.
  await verifyChain({ chain: restricted.chain, rootVerifier: restricted.rootVerifier, ...baseOptions });

  await assert.rejects(
    verifyChain({
      chain: serializeChain([restricted.root, permissive.hop1, restricted.hop2]),
      rootVerifier: restricted.rootVerifier,
      ...baseOptions,
    }),
    (error: Error) => error instanceof DelegateSdJwtError && /sd_hash mismatch/.test(error.message),
  );
});

test('issuer_jwt_hash binds a hop while letting the previous disclosures be redacted', async () => {
  const fixture = await buildFixture({ hop1HashMode: 'issuer_jwt_hash' });
  const tokens = splitChain(fixture.chain);
  const root = tokens[0]!;
  // The agent drops the card number before presenting; issuer_jwt_hash survives.
  const redacted = root.issuerJwt + '~' + root.disclosures[0] + '~';
  const { payloads } = await verifyChain({
    chain: serializeChain([redacted, fixture.hop1, fixture.hop2]),
    rootVerifier: fixture.rootVerifier,
    ...baseOptions,
  });
  const rootPayload = payloads[0] as JsonObject;
  assert.equal(rootPayload['cardholder'], 'A. Holder');
  assert.equal(rootPayload['card_number'], undefined, 'the redacted claim must be absent');
});

test('sd_hash does not survive redaction of the previous disclosures', async () => {
  const fixture = await buildFixture();
  const tokens = splitChain(fixture.chain);
  const root = tokens[0]!;
  const redacted = root.issuerJwt + '~' + root.disclosures[0] + '~';
  await assert.rejects(
    verifyChain({
      chain: serializeChain([redacted, fixture.hop1, fixture.hop2]),
      rootVerifier: fixture.rootVerifier,
      ...baseOptions,
    }),
    (error: Error) => error instanceof DelegateSdJwtError && /sd_hash mismatch/.test(error.message),
  );
});

test('a single-hop chain verifies', async () => {
  const issuer = await generateEcKey();
  const holder = await generateEcKey();
  const root = await issueSdJwtVc({
    issuer,
    plain: { iss: 'https://issuer.example', vct: 'urn:example:vct', cnf: { jwk: holder.publicJwk } },
    disclosed: { given_name: 'Ada' },
  });
  const terminal = await createKbSdJwt({
    prevToken: root,
    claims: { purpose: 'age check' },
    aud: AUD,
    nonce: PRESENTATION_NONCE,
    alg: holder.alg,
    signer: holder.signer,
    hasher,
    saltGenerator,
    iat: NOW,
  });
  const { payloads } = await verifyChain({
    chain: serializeChain([root, terminal]),
    rootVerifier: rootVerifierFor(issuer.publicJwk),
    ...baseOptions,
  });
  assert.equal(payloads.length, 2);
  assert.equal((payloads[1] as JsonObject)['purpose'], 'age check');
});

test('a root with no disclosures can be delegated', async () => {
  // A credential whose claims are all plain has no disclosures, so inside the
  // chain it is a bare `<jwt>` with no separator of its own.
  const issuer = await generateEcKey();
  const holder = await generateEcKey();
  const root = await issueSdJwtVc({
    issuer,
    plain: { iss: 'https://issuer.example', vct: 'urn:example:vct', cnf: { jwk: holder.publicJwk } },
    disclosed: {},
  });
  assert.equal(root.split('~').length, 2, 'root has no disclosure components');

  const terminal = await createKbSdJwt({
    prevToken: root,
    claims: { purpose: 'age check' },
    aud: AUD,
    nonce: PRESENTATION_NONCE,
    alg: holder.alg,
    signer: holder.signer,
    hasher,
    saltGenerator,
    iat: NOW,
  });
  const chain = serializeChain([root, terminal]);
  assert.equal(splitChain(chain).length, 2);

  const { payloads } = await verifyChain({
    chain,
    rootVerifier: rootVerifierFor(issuer.publicJwk),
    ...baseOptions,
  });
  assert.equal((payloads[0] as JsonObject)['vct'], 'urn:example:vct');
  assert.equal((payloads[1] as JsonObject)['purpose'], 'age check');
});

test('verifies a four-hop chain (user → agent → sub-agent → merchant)', async () => {
  // Chain depth is unbounded: every intermediate hop names the next key, and
  // only the last hop is terminal.
  const issuer = await generateEcKey();
  const holder = await generateEcKey();
  const agent = await generateEcKey();
  const subAgent = await generateEcKey();

  const root = await issueSdJwtVc({
    issuer,
    plain: { iss: 'https://issuer.example', vct: 'urn:example:card', cnf: { jwk: holder.publicJwk } },
    disclosed: { cardholder: 'A. Holder' },
  });

  const hop = async (prevToken: string, signer: (typeof holder)['signer'], claims: JsonObject, nonce: string) =>
    createKbSdJwt({
      prevToken,
      claims,
      aud: AUD,
      nonce,
      alg: 'ES256',
      signer,
      hasher,
      saltGenerator,
      iat: NOW,
    });

  const toAgent = await hop(
    root,
    holder.signer,
    { cnf: { jwk: agent.publicJwk }, scope: 'payment', max_amount: '50.00' },
    'agent-nonce',
  );
  const toSubAgent = await hop(
    toAgent,
    agent.signer,
    { cnf: { jwk: subAgent.publicJwk }, scope: 'payment', max_amount: '20.00' },
    'sub-agent-nonce',
  );
  const presentation = await hop(
    toSubAgent,
    subAgent.signer,
    { amount: '12.00', merchant: 'shoes.example' },
    PRESENTATION_NONCE,
  );

  const { payloads, tokens } = await verifyChain({
    chain: serializeChain([root, toAgent, toSubAgent, presentation]),
    rootVerifier: rootVerifierFor(issuer.publicJwk),
    ...baseOptions,
  });

  assert.equal(tokens.length, 4);
  assert.deepEqual(
    tokens.map((token) => token.typ),
    ['dc+sd-jwt', 'kb+sd-jwt+kb', 'kb+sd-jwt+kb', 'kb+sd-jwt'],
  );
  // The scope narrows at each hop; enforcing that narrowing is application policy.
  assert.equal((payloads[1] as JsonObject)['max_amount'], '50.00');
  assert.equal((payloads[2] as JsonObject)['max_amount'], '20.00');
  assert.equal((payloads[3] as JsonObject)['amount'], '12.00');
});

test('createRootSdJwt anchors a chain from a delegate-payload root', async () => {
  const issuer = await generateEcKey();
  const holder = await generateEcKey();
  const root = await createRootSdJwt({
    claims: { cnf: { jwk: holder.publicJwk }, mandate: 'shopping', budget: '100.00' },
    alg: issuer.alg,
    signer: issuer.signer,
    hasher,
    saltGenerator,
    kid: 'issuer-key-1',
    extraClaims: { iss: 'https://issuer.example', iat: NOW - 60 },
  });
  const terminal = await createKbSdJwt({
    prevToken: root,
    claims: { amount: '7.00' },
    aud: AUD,
    nonce: PRESENTATION_NONCE,
    alg: holder.alg,
    signer: holder.signer,
    hasher,
    saltGenerator,
    iat: NOW,
  });

  const { payloads, tokens } = await verifyChain({
    chain: serializeChain([root, terminal]),
    rootVerifier: rootVerifierFor(issuer.publicJwk),
    ...baseOptions,
  });

  assert.equal(tokens[0]?.header['kid'], 'issuer-key-1');
  // The root has a delegate_payload, so its disclosed item is the effective payload.
  const grant = payloads[0] as JsonObject;
  assert.equal(grant['mandate'], 'shopping');
  assert.equal(grant['budget'], '100.00');
  assert.equal((payloads[1] as JsonObject)['amount'], '7.00');
});

/** Re-encode a disclosure with a mutated value, keeping it well-formed. */
function forgeDisclosure(disclosure: string): string {
  const [salt, ...rest] = JSON.parse(
    Buffer.from(disclosure, 'base64url').toString('utf8'),
  ) as unknown[];
  const forged = rest.length === 1 ? [salt, 'tampered'] : [salt, rest[0], 'tampered'];
  return Buffer.from(JSON.stringify(forged), 'utf8').toString('base64url');
}
