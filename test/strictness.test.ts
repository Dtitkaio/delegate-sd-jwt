/**
 * The verifier-strictness contract. Each of these is a documented weakness in
 * at least one shipping SD-JWT implementation, so each one gets a test.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  computeDisclosureDigest,
  createDisclosure,
  createKbSdJwt,
  DEFAULT_SD_ALG,
  DelegateSdJwtError,
  parseToken,
  resolveDisclosures,
  serializeChain,
  splitChain,
  verifyChain,
  verifySdJwt,
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
  signJwt,
  type TestKey,
} from './helpers.js';

const alwaysValid = () => true;

/** Build a compact SD-JWT with a hand-written payload, header, and disclosures. */
async function handRolled(options: {
  key: TestKey;
  payload: JsonObject;
  disclosures?: readonly string[];
  header?: JsonObject;
}): Promise<string> {
  const header: JsonObject = { alg: options.key.alg, ...options.header };
  const jwt = await signJwt(header, options.payload, options.key.signer);
  return [jwt, ...(options.disclosures ?? [])].join('~') + '~';
}

async function digestOf(disclosure: string): Promise<string> {
  return computeDisclosureDigest(disclosure, DEFAULT_SD_ALG, hasher);
}

function rawDisclosure(parts: unknown[]): string {
  return Buffer.from(JSON.stringify(parts), 'utf8').toString('base64url');
}

test("rejects alg 'none'", async () => {
  const payload = Buffer.from(JSON.stringify({ iss: 'x' }), 'utf8').toString('base64url');
  const header = Buffer.from(JSON.stringify({ alg: 'none' }), 'utf8').toString('base64url');
  assert.throws(
    () => parseToken(`${header}.${payload}.~`),
    (error: Error) => error instanceof DelegateSdJwtError && /must not be 'none'/.test(error.message),
  );
});

test('rejects a non-string alg', async () => {
  const payload = Buffer.from(JSON.stringify({ iss: 'x' }), 'utf8').toString('base64url');
  const header = Buffer.from(JSON.stringify({ alg: 42 }), 'utf8').toString('base64url');
  assert.throws(
    () => parseToken(`${header}.${payload}.~`),
    (error: Error) =>
      error instanceof DelegateSdJwtError && /must be a non-empty string/.test(error.message),
  );
});

test('rejects a malformed disclosure', async () => {
  const key = await generateEcKey();
  const bogus = rawDisclosure(['salt', 'name', 'value', 'extra']);
  const token = await handRolled({
    key,
    payload: { _sd_alg: DEFAULT_SD_ALG, _sd: [await digestOf(bogus)] },
    disclosures: [bogus],
  });
  await assert.rejects(
    verifySdJwt({ token, verifier: alwaysValid, hasher }),
    (error: Error) =>
      error instanceof DelegateSdJwtError &&
      /must be \[salt, value\] or \[salt, name, value\]/.test(error.message),
  );
});

test('rejects a disclosure whose salt is not a string', async () => {
  const key = await generateEcKey();
  const bogus = rawDisclosure([1234, 'name', 'value']);
  const token = await handRolled({
    key,
    payload: { _sd_alg: DEFAULT_SD_ALG, _sd: [await digestOf(bogus)] },
    disclosures: [bogus],
  });
  await assert.rejects(
    verifySdJwt({ token, verifier: alwaysValid, hasher }),
    (error: Error) => error instanceof DelegateSdJwtError && /salt must be a string/.test(error.message),
  );
});

test('rejects duplicate disclosure digests', async () => {
  const key = await generateEcKey();
  const disclosure = createDisclosure('value', saltGenerator, 'claim');
  const token = await handRolled({
    key,
    payload: { _sd_alg: DEFAULT_SD_ALG, _sd: [await digestOf(disclosure)] },
    disclosures: [disclosure, disclosure],
  });
  await assert.rejects(
    verifySdJwt({ token, verifier: alwaysValid, hasher }),
    (error: Error) =>
      error instanceof DelegateSdJwtError && /Duplicate disclosure digest/.test(error.message),
  );
});

test('rejects a digest referenced twice', async () => {
  const key = await generateEcKey();
  const disclosure = createDisclosure('value', saltGenerator, 'claim');
  const digest = await digestOf(disclosure);
  const token = await handRolled({
    key,
    payload: { _sd_alg: DEFAULT_SD_ALG, _sd: [digest, digest] },
    disclosures: [disclosure],
  });
  await assert.rejects(
    verifySdJwt({ token, verifier: alwaysValid, hasher }),
    (error: Error) =>
      error instanceof DelegateSdJwtError && /referenced more than once/.test(error.message),
  );
});

test('rejects _sd that is not an array of strings', async () => {
  const key = await generateEcKey();
  const token = await handRolled({
    key,
    payload: { _sd_alg: DEFAULT_SD_ALG, _sd: [{ nested: true }] },
  });
  await assert.rejects(
    verifySdJwt({ token, verifier: alwaysValid, hasher }),
    (error: Error) =>
      error instanceof DelegateSdJwtError &&
      /'_sd' must be an array of digest strings/.test(error.message),
  );
});

test('rejects a disclosed claim that collides with an existing claim', async () => {
  const key = await generateEcKey();
  const disclosure = createDisclosure('disclosed', saltGenerator, 'iss');
  const token = await handRolled({
    key,
    payload: { _sd_alg: DEFAULT_SD_ALG, iss: 'https://issuer.example', _sd: [await digestOf(disclosure)] },
    disclosures: [disclosure],
  });
  await assert.rejects(
    verifySdJwt({ token, verifier: alwaysValid, hasher }),
    (error: Error) =>
      error instanceof DelegateSdJwtError && /collides with an existing claim/.test(error.message),
  );
});

test("rejects a disclosed claim named '_sd' or '...'", async () => {
  for (const name of ['_sd', '...']) {
    const key = await generateEcKey();
    const disclosure = rawDisclosure(['salt', name, 'value']);
    const token = await handRolled({
      key,
      payload: { _sd_alg: DEFAULT_SD_ALG, _sd: [await digestOf(disclosure)] },
      disclosures: [disclosure],
    });
    await assert.rejects(
      verifySdJwt({ token, verifier: alwaysValid, hasher }),
      (error: Error) =>
        error instanceof DelegateSdJwtError && /claim name must not be/.test(error.message),
      `claim name ${name} must be rejected`,
    );
  }
});

test('rejects an unsupported _sd_alg', async () => {
  const key = await generateEcKey();
  const token = await handRolled({ key, payload: { _sd_alg: 'md5', _sd: [] } });
  await assert.rejects(
    verifySdJwt({ token, verifier: alwaysValid, hasher }),
    (error: Error) => error instanceof DelegateSdJwtError && /Unsupported _sd_alg/.test(error.message),
  );
});

test('rejects an object-property disclosure used as an array element', async () => {
  const key = await generateEcKey();
  const disclosure = createDisclosure('value', saltGenerator, 'claim');
  const token = await handRolled({
    key,
    payload: { _sd_alg: DEFAULT_SD_ALG, list: [{ '...': await digestOf(disclosure) }] },
    disclosures: [disclosure],
  });
  await assert.rejects(
    verifySdJwt({ token, verifier: alwaysValid, hasher }),
    (error: Error) =>
      error instanceof DelegateSdJwtError &&
      /Array-element disclosure must be \[salt, value\]/.test(error.message),
  );
});

test('rejects an array-element disclosure used as an object property', async () => {
  const key = await generateEcKey();
  const disclosure = createDisclosure('value', saltGenerator);
  const token = await handRolled({
    key,
    payload: { _sd_alg: DEFAULT_SD_ALG, _sd: [await digestOf(disclosure)] },
    disclosures: [disclosure],
  });
  await assert.rejects(
    verifySdJwt({ token, verifier: alwaysValid, hasher }),
    (error: Error) =>
      error instanceof DelegateSdJwtError &&
      /Object-property disclosure must be \[salt, name, value\]/.test(error.message),
  );
});

test("rejects '...' as an object property name", async () => {
  const key = await generateEcKey();
  const token = await handRolled({
    key,
    payload: { _sd_alg: DEFAULT_SD_ALG, '...': 'digest', other: 1 },
  });
  await assert.rejects(
    verifySdJwt({ token, verifier: alwaysValid, hasher }),
    (error: Error) =>
      error instanceof DelegateSdJwtError &&
      /only valid as an array-element disclosure reference/.test(error.message),
  );
});

test('drops undisclosed array elements and ignores decoy digests', async () => {
  const key = await generateEcKey();
  const kept = createDisclosure('kept', saltGenerator);
  const token = parseToken(
    await handRolled({
      key,
      payload: {
        _sd_alg: DEFAULT_SD_ALG,
        list: [{ '...': await digestOf(kept) }, { '...': 'decoy-digest-not-present' }],
        _sd: ['another-decoy'],
      },
      disclosures: [kept],
    }),
  );
  const payload = await resolveDisclosures(token, hasher);
  assert.deepEqual(payload['list'], ['kept']);
});

test('rejects a KB-SD-JWT carrying both binding claims', async () => {
  const fixture = await buildFixture();
  const forged = await forgeHop(fixture, (payload) => {
    payload['issuer_jwt_hash'] = payload['sd_hash'];
  });
  await assert.rejects(
    verifyForged(fixture, forged),
    (error: Error) =>
      error instanceof DelegateSdJwtError && /exactly one of 'sd_hash'/.test(error.message),
  );
});

test('rejects a KB-SD-JWT carrying neither binding claim', async () => {
  const fixture = await buildFixture();
  const forged = await forgeHop(fixture, (payload) => {
    delete payload['sd_hash'];
  });
  await assert.rejects(
    verifyForged(fixture, forged),
    (error: Error) =>
      error instanceof DelegateSdJwtError && /exactly one of 'sd_hash'/.test(error.message),
  );
});

test("rejects a KB-SD-JWT with no 'iat'", async () => {
  const fixture = await buildFixture();
  const forged = await forgeHop(fixture, (payload) => {
    delete payload['iat'];
  });
  await assert.rejects(
    verifyForged(fixture, forged),
    (error: Error) => error instanceof DelegateSdJwtError && /missing required 'iat'/.test(error.message),
  );
});

test('rejects a non-numeric exp', async () => {
  const fixture = await buildFixture({ hop2Claims: { exp: 'soon' } });
  await assert.rejects(
    verifyChain({
      chain: fixture.chain,
      rootVerifier: fixture.rootVerifier,
      jwkVerifierFactory,
      hasher,
      expectedAud: AUD,
      expectedNonce: PRESENTATION_NONCE,
      currentTime: NOW + 60,
    }),
    (error: Error) => error instanceof DelegateSdJwtError && /invalid 'exp' claim/.test(error.message),
  );
});

test('rejects a terminal typ that delegates onward', async () => {
  const fixture = await buildFixture();
  // The agent claims a terminal typ while still naming a further delegate.
  const nextDelegate = await generateEcKey();
  const forged = await forgeHop(
    fixture,
    () => undefined,
    { typ: 'kb+sd-jwt' },
    { cnf: { jwk: nextDelegate.publicJwk }, amount: '1.00' },
  );
  await assert.rejects(
    verifyForged(fixture, forged),
    (error: Error) => error instanceof DelegateSdJwtError && /MUST NOT carry a 'cnf'/.test(error.message),
  );
});

test('rejects an intermediate typ with no onward key', async () => {
  // Checked in handoff mode, where an intermediate final hop is the expected
  // shape — so the missing `cnf`, not the position, is what fails.
  const fixture = await buildFixture();
  const forged = await forgeHop(fixture, () => undefined, { typ: 'kb+sd-jwt+kb' }, { amount: '1.00' });
  await assert.rejects(
    verifyForged(fixture, forged, { role: 'delegate' }),
    (error: Error) => error instanceof DelegateSdJwtError && /requires a 'cnf'/.test(error.message),
  );
});

test('rejects an unknown typ on a hop', async () => {
  const fixture = await buildFixture();
  const forged = await forgeHop(fixture, () => undefined, { typ: 'jwt' });
  await assert.rejects(
    verifyForged(fixture, forged),
    (error: Error) => error instanceof DelegateSdJwtError && /Unexpected JWT typ/.test(error.message),
  );
});

test('accepts the legacy kb-sd-jwt typ alias', async () => {
  const fixture = await buildFixture();
  const forged = await forgeHop(fixture, () => undefined, { typ: 'kb-sd-jwt' });
  const { payloads } = await verifyForged(fixture, forged);
  assert.equal(payloads.length, 3);
});

test('rejects a detached KB-JWT (dSD-JWT+KB is out of scope)', async () => {
  const fixture = await buildFixture();
  const chain = serializeChain([fixture.root, fixture.hop1, fixture.hop2]);
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'kb+jwt' }), 'utf8').toString(
    'base64url',
  );
  await assert.rejects(
    verifyChain({
      chain: `${chain}${header}.e30.sig`,
      rootVerifier: fixture.rootVerifier,
      jwkVerifierFactory,
      hasher,
      currentTime: NOW + 60,
    }),
    (error: Error) =>
      error instanceof DelegateSdJwtError && /detached KB-JWT/.test(error.message),
  );
});

test('rejects a bare credential replayed as a presentation', async () => {
  // Anyone holding a copy of the credential could otherwise replay it: with no
  // hop, no key-binding signature exists and expectedAud/expectedNonce would
  // have nothing to match against.
  const fixture = await buildFixture();
  await assert.rejects(
    verifyChain({
      chain: fixture.root,
      rootVerifier: fixture.rootVerifier,
      jwkVerifierFactory,
      hasher,
      expectedAud: AUD,
      expectedNonce: PRESENTATION_NONCE,
      currentTime: NOW + 60,
    }),
    (error: Error) =>
      error instanceof DelegateSdJwtError &&
      /must contain at least one KB-SD-JWT hop/.test(error.message),
  );
});

test('a delegate cannot pose as the original holder', async () => {
  const fixture = await buildFixture();
  const rogue = await generateEcKey();
  // The agent holds only its own key. To present the credential as the holder it
  // would have to sign the first hop with the key named in the root's cnf.
  const forgedFirstHop = await createKbSdJwt({
    prevToken: fixture.root,
    claims: { amount: '9999.00' },
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
      chain: serializeChain([fixture.root, forgedFirstHop]),
      rootVerifier: fixture.rootVerifier,
      jwkVerifierFactory,
      hasher,
      expectedAud: AUD,
      expectedNonce: PRESENTATION_NONCE,
      currentTime: NOW + 60,
    }),
    (error: Error) =>
      error instanceof DelegateSdJwtError && /Signature verification failed/.test(error.message),
  );
});

test('a delegate cannot shorten the chain to hide the delegation', async () => {
  // Dropping the middle hop of user → agent → sub-agent → merchant breaks both
  // the cnf walk and the binding of whatever follows.
  const fixture = await buildFixture();
  await assert.rejects(
    verifyChain({
      chain: serializeChain([fixture.root, fixture.hop2]),
      rootVerifier: fixture.rootVerifier,
      jwkVerifierFactory,
      hasher,
      expectedAud: AUD,
      expectedNonce: PRESENTATION_NONCE,
      currentTime: NOW + 60,
    }),
    (error: Error) => error instanceof DelegateSdJwtError,
  );
});

test('rejects a KB-JWT attached to a non-final token', async () => {
  const fixture = await buildFixture();
  const kbJwt = 'aGVhZGVy.cGF5bG9hZA.c2ln';
  assert.throws(
    () => splitChain(`${fixture.root.slice(0, -1)}~${kbJwt}~~${fixture.hop1.slice(0, -1)}~`),
    (error: Error) => error instanceof DelegateSdJwtError && /detached KB-JWT/.test(error.message),
  );
});

test('rejects a chain with an empty disclosure component inside a token', async () => {
  const fixture = await buildFixture();
  const tokens = splitChain(fixture.chain);
  const root = tokens[0]!;
  await assert.rejects(
    verifyChain({
      chain: serializeChain([`${root.issuerJwt}~~${root.disclosures[0]}~`, fixture.hop1]),
      rootVerifier: fixture.rootVerifier,
      jwkVerifierFactory,
      hasher,
      currentTime: NOW + 60,
    }),
    (error: Error) => error instanceof DelegateSdJwtError,
  );
});

test('cnfJwk is unavailable before verification', async () => {
  const fixture = await buildFixture();
  const [root] = splitChain(fixture.chain);
  assert.throws(
    () => root!.cnfJwk(),
    (error: Error) => error instanceof DelegateSdJwtError && /has not been verified/.test(error.message),
  );
});

test('a root with no cnf cannot be delegated', async () => {
  const issuer = await generateEcKey();
  const holder = await generateEcKey();
  const root = await issueSdJwtVc({
    issuer,
    plain: { iss: 'https://issuer.example', vct: 'urn:example:vct' },
    disclosed: { given_name: 'Ada' },
  });
  const hop = await createKbSdJwt({
    prevToken: root,
    claims: { purpose: 'test' },
    aud: AUD,
    nonce: PRESENTATION_NONCE,
    alg: holder.alg,
    signer: holder.signer,
    hasher,
    saltGenerator,
    iat: NOW,
  });
  await assert.rejects(
    verifyChain({
      chain: serializeChain([root, hop]),
      rootVerifier: rootVerifierFor(issuer.publicJwk),
      jwkVerifierFactory,
      hasher,
      currentTime: NOW + 60,
    }),
    (error: Error) => error instanceof DelegateSdJwtError && /does not provide a cnf\.jwk/.test(error.message),
  );
});

/**
 * Re-sign the terminal hop with the agent's key after mutating its payload,
 * header, or delegate claims. Everything the forger controls is legitimately
 * theirs — only the chain rules should stop them.
 */
async function forgeHop(
  fixture: Awaited<ReturnType<typeof buildFixture>>,
  mutate: (payload: JsonObject) => void,
  header?: JsonObject,
  delegateClaims?: JsonObject,
): Promise<string> {
  const hop2 = splitChain(fixture.chain)[2]!;
  const payload = { ...hop2.payload };
  let disclosures = [...hop2.disclosures];
  if (delegateClaims !== undefined) {
    const disclosure = createDisclosure(delegateClaims, saltGenerator);
    disclosures = [disclosure];
    payload['delegate_payload'] = [{ '...': await digestOf(disclosure) }];
  }
  mutate(payload);
  const jwt = await signJwt(
    { alg: fixture.agent.alg, typ: hop2.typ, ...header },
    payload,
    fixture.agent.signer,
  );
  return [jwt, ...disclosures].join('~') + '~';
}

async function verifyForged(
  fixture: Awaited<ReturnType<typeof buildFixture>>,
  forgedHop: string,
  overrides: { role?: 'verifier' | 'delegate' } = {},
): Promise<{ payloads: JsonObject[] }> {
  return verifyChain({
    chain: serializeChain([fixture.root, fixture.hop1, forgedHop]),
    rootVerifier: fixture.rootVerifier,
    jwkVerifierFactory,
    hasher,
    expectedAud: AUD,
    expectedNonce: PRESENTATION_NONCE,
    currentTime: NOW + 60,
    ...overrides,
  });
}
