# delegate-sd-jwt

Zero-dependency TypeScript implementation of **Delegate SD-JWT (dSD-JWT)** — verifiable
delegation chains built on RFC 9901 SD-JWT.

A credential holder delegates a down-scoped, verifiable presentation to a *delegate holder* —
a person to an AI agent, an agent to another agent — and a verifier validates the entire chain
back to the original issuer.

```
issuer ──signs──▶ SD-JWT VC ──user delegates──▶ KB-SD-JWT ──agent presents──▶ KB-SD-JWT
                  cnf: user                     cnf: agent                    (terminal)
                        └────────── verifier checks the whole chain ──────────┘
```

- **No runtime dependencies.** Hashing, signing, and signature verification are injected, so
  private keys can stay inside a wallet, KMS, or HSM and never enter this library.
- **Strict verifier.** Malformed disclosures, duplicate digests, `alg: none`, claim-name
  collisions, and unsupported `_sd_alg` values are rejected rather than tolerated.
- **Format constants in one place.** `typ` values, claim names, and the `~~` chain separator
  are exported from a single module, because the draft is at `-00` and they will move.

## Status

Implements [`draft-gco-oauth-delegate-sd-jwt-00`](https://www.ietf.org/archive/id/draft-gco-oauth-delegate-sd-jwt-00.html),
an individual draft that is pre-adoption in the OAuth working group. Expect format churn.

Behaviour is aligned with the [Google AP2 Python SDK](https://github.com/google-agentic-commerce/AP2)
(`code/sdk/python/ap2/sdk/sdjwt/`) as the de facto interop target, and with
[RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html) for SD-JWT itself.

## Install

```bash
npm install delegate-sd-jwt
```

Node ≥ 20, or any runtime with WebCrypto. The bundled WebCrypto backend supports EC keys
(ES256 / ES384 / ES512); other algorithms are supported by injecting your own verifier factory.

## Quickstart

### The holder delegates

```ts
import {
  createKbSdJwt,
  serializeChain,
  webcryptoHasher,
  webcryptoSaltGenerator,
  webcryptoSigner,
} from 'delegate-sd-jwt';

// `credential` is any RFC 9901 SD-JWT whose payload carries the holder's `cnf.jwk`
// — an SD-JWT VC straight out of a wallet needs no re-issuance.
const grant = await createKbSdJwt({
  prevToken: credential,
  claims: {
    cnf: { jwk: agentPublicJwk }, // presence of `cnf` makes this an intermediate hop
    scope: 'payment',
    max_amount: '50.00',
    exp: Math.floor(Date.now() / 1000) + 3600, // keep delegations short-lived
  },
  aud: 'https://merchant.example',
  nonce: agentNonce,
  alg: 'ES256',
  signer: webcryptoSigner(holderPrivateKey, 'ES256'), // or a KMS-backed signer
  hasher: webcryptoHasher,
  saltGenerator: webcryptoSaltGenerator,
});
```

### The delegate presents

```ts
const presentation = await createKbSdJwt({
  prevToken: grant,
  claims: { amount: '42.00', merchant: 'shoes.example' }, // no `cnf` ⇒ terminal hop
  aud: 'https://merchant.example',
  nonce: verifierNonce,
  alg: 'ES256',
  signer: webcryptoSigner(agentPrivateKey, 'ES256'),
  hasher: webcryptoHasher,
  saltGenerator: webcryptoSaltGenerator,
});

const chain = serializeChain([credential, grant, presentation]);
```

### The verifier checks the chain

```ts
import { verifyChain, webcryptoHasher, webcryptoJwkVerifier } from 'delegate-sd-jwt';

const { payloads } = await verifyChain({
  chain,
  rootVerifier: ({ header }) => resolveIssuerKey(header), // kid / x5c / DID → Verifier
  jwkVerifierFactory: webcryptoJwkVerifier,
  hasher: webcryptoHasher,
  expectedAud: 'https://merchant.example',
  expectedNonce: verifierNonce,
});

// payloads[0] — the credential's resolved claims
// payloads[1] — what the user granted the agent
// payloads[2] — what the agent is presenting
```

`verifyChain` proves the chain is cryptographically sound. Whether the presented payload is
*permitted* by the grant above it — amount limits, merchant allow-lists, scopes — is
application policy, and deliberately not this library's job.

## API

| Export | Purpose |
| --- | --- |
| `createRootSdJwt` | Issue a root SD-JWT whose claims are a selectively-disclosable `delegate_payload` |
| `createKbSdJwt` | Sign one delegation hop, bound to the token it delegates |
| `createDisclosure` | Build a raw RFC 9901 disclosure string |
| `serializeChain` / `splitChain` | Join tokens into a dSD-JWT / split one back apart |
| `verifyChain` | Verify a whole chain and return the per-hop effective payloads |
| `verifySdJwt` / `verifyKbSdJwt` | Verify a single token |
| `parseToken` / `ParsedToken` | Parse a compact SD-JWT; `cnfJwk()` yields the next hop's key |
| `resolveDisclosures` | Strict RFC 9901 §7.1 disclosure processing |
| `computeSdHash` / `computeIssuerJwtHash` / `verifyBinding` | Chain-binding primitives |
| `webcrypto*` / `importEcPrivateKey` | Optional default crypto backend (EC only) |

Injected-crypto types: `Hasher`, `Signer`, `Verifier`, `JwkVerifierFactory`, `SaltGenerator`,
`RootVerifierResolver`. Every failure raises `DelegateSdJwtError`.

## Wire format

```
<root jwt>~<disclosure>~~<hop 1 jwt>~<disclosure>~~<hop 2 jwt>~<disclosure>~
```

Tokens are joined so that an *empty* disclosure component (`~~`) separates each SD-JWT from
the next KB-SD-JWT. The trailing `~` marks a dSD-JWT with no detached final KB-JWT.

Each hop is itself an SD-JWT, signed by the key named in the previous hop's `cnf.jwk`:

| | Intermediate hop | Terminal hop |
| --- | --- | --- |
| `typ` | `kb+sd-jwt+kb` | `kb+sd-jwt` |
| `cnf` in delegate payload | required | forbidden |

Hop payload claims: `_sd_alg`, `iat`, `aud`, `nonce`, `delegate_payload`, and **exactly one**
of `sd_hash` (hashes the previous token's JWT *and* disclosures) or `issuer_jwt_hash` (hashes
only the previous JWT, so the next delegate may redact earlier disclosures).

Legacy `typ` aliases `kb-sd-jwt` and `kb-sd-jwt+kb` are accepted when verifying.

## Security notes

`verifyChain` rejects, and each of these has a test:

- `alg: none`, or a non-string `alg`
- disclosures that are not `[salt, value]` / `[salt, name, value]`, or whose salt is not a string
- duplicate disclosure digests, and any digest referenced more than once
- `_sd` that is not an array of strings; `...` used outside an array-element reference
- a disclosed claim name that collides with an existing claim, or is `_sd` / `...`
- an `_sd_alg` other than `sha-256`, `sha-384`, `sha-512`
- both binding claims present, neither present, or one that does not match the previous token
- a hop that is not signed by the previous hop's `cnf.jwk`
- a missing `iat`; a mismatched `aud` / `nonce` on the final hop
- `exp` in the past or `iat` in the future (configurable skew, default 300 s), including
  inside a disclosed delegate payload
- a terminal `typ` that delegates onward, or an intermediate `typ` that does not
- anything other than exactly one disclosed `delegate_payload` element, unless
  `allowMultipleFinalDelegateItems` is set for a delegate-to-delegate handoff

Two properties worth calling out:

**The binding is checked in both directions.** A hop's `sd_hash` must match the token it
delegates, and every hop in the chain is checked. Skipping either half lets a delegate splice
hops from different chains together when a holder `cnf` is reused (draft §8.1). There is a
test that mounts exactly that attack with two genuinely-signed grants.

**Delegation revocation is an open problem** (draft §8.3). Until the draft settles, use short
`exp` values on delegate payloads.

This library does its own SD-JWT verification rather than delegating to a general-purpose
SD-JWT library, because the strictness list above is the whole point: a July 2026 RFC 9901
conformance audit ([sd-jwt-js#388](https://github.com/openwallet-foundation/sd-jwt-js/issues/388))
found a widely-used verifier accepting `alg: none`, malformed disclosures, and disclosed
expired `exp` values.

## Not implemented

- **dSD-JWT+KB** — a chain with a detached trailing KB-JWT. Such a chain is *rejected* rather
  than silently accepted with an unverified final token. AP2 does not use this variant; key
  binding is built into the terminal KB-SD-JWT.
- **OpenID4VP `transaction_data` transport** (draft §7.1) — the `transaction_type: "delegate"`
  entries belong in the presentation layer, not here.
- **Per-field selective disclosure inside a delegate payload.** `createKbSdJwt` discloses the
  delegate payload as one array element. The verifier resolves nested `_sd` structures, so
  tokens produced elsewhere with per-field disclosures verify correctly.

## Integrating with a wallet framework

Nothing in this library depends on a wallet SDK. Two adapters connect it to one:

**Signing through the wallet's key management**, so private keys never reach application code:

```ts
const walletSigner = (keyId: string): Signer => async (signingInput) => {
  const { signature } = await agent.kms.sign({
    keyId,
    data: utf8Bytes(signingInput),
    algorithm: 'ES256',
  });
  return encodeBase64Url(signature);
};
```

**Resolving the root issuer key** from a DID or an `x5c` chain:

```ts
const rootVerifier: RootVerifierResolver = async ({ header, payload }) => {
  const jwk = await resolveIssuerJwk(header, payload); // DID resolution, or x5c + trust roots
  return webcryptoJwkVerifier(jwk, header['alg'] as string);
};
```

For Ed25519 issuer keys — common in DID-based deployments — inject a `JwkVerifierFactory`
built on an EdDSA library instead of `webcryptoJwkVerifier`. WebCrypto's Ed25519 support is
not portable enough to depend on here.

## Development

```bash
npm install && npm test
```

`npm test` builds with `tsc` and runs the suite on `node:test`.

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution.
