# 02. Security Architecture

## 1. Scope

`dlms-security` is a pure application-security library. It executes security
algorithms and policy checks for higher layers without owning transport,
association state, xDLMS dispatch, or COSEM object storage.

## 2. Layer Diagram

```mermaid
flowchart TB
  Association["dlms-association"]
  XDlms["dlms-xdlms"]
  Server["dlms-server"]
  Client["dlms-client"]
  Cosem["dlms-cosem"]

  Security["dlms-security"]

  Association --> Security
  XDlms --> Security
  Server --> Security
  Client --> Security
  Cosem --> Security

  Security --> Suite["Security suite model"]
  Security --> Keys["IKeyStore"]
  Security --> Counters["IInvocationCounterStore"]
  Security --> Cipher["CipheredApduProcessor"]
  Security --> Hls["HlsGmacAuthenticator"]
```

## 3. Module Map

```text
include/dlms/security/security_status.hpp
include/dlms/security/security_types.hpp
include/dlms/security/key_store.hpp
include/dlms/security/invocation_counter_store.hpp
include/dlms/security/random_source.hpp
include/dlms/security/ciphered_apdu_processor.hpp
include/dlms/security/hls_gmac_authenticator.hpp
src/security/...
test/security/...
```

## 4. Class Interaction Diagram

```mermaid
classDiagram
  class SecurityContext {
    +SecuritySuite suite
    +SecurityPolicy policy
    +uint8_t localSystemTitle[8]
    +uint8_t remoteSystemTitle[8]
  }

  class SecurityKey {
    +SecurityKeyRole role
    +uint8_t bytes[32]
    +size_t size
  }

  class IKeyStore {
    <<interface>>
    +GetKey(role, output)
  }

  class IInvocationCounterStore {
    <<interface>>
    +NextLocal(output)
    +ValidateRemote(counter)
  }

  class IRandomSource {
    <<interface>>
    +Fill(output, size)
  }

  class CipheredApduProcessor {
    +Protect(plain, protected)
    +Unprotect(protected, plain)
  }

  class HlsGmacAuthenticator {
    +BuildChallenge(output)
    +BuildResponse(challenge, output)
    +VerifyResponse(challenge, response)
  }

  class AesGcmSuite0 {
    +Seal()
    +Open()
  }

  CipheredApduProcessor --> SecurityContext
  CipheredApduProcessor --> IKeyStore
  CipheredApduProcessor --> IInvocationCounterStore
  CipheredApduProcessor --> AesGcmSuite0

  HlsGmacAuthenticator --> SecurityContext
  HlsGmacAuthenticator --> IKeyStore
  HlsGmacAuthenticator --> IInvocationCounterStore
  HlsGmacAuthenticator --> IRandomSource
  HlsGmacAuthenticator --> AesGcmSuite0
```

## 5. APDU Protection Flow

```mermaid
sequenceDiagram
  participant Caller
  participant Processor as CipheredApduProcessor
  participant Keys as IKeyStore
  participant Counters as IInvocationCounterStore
  participant GCM as AesGcmSuite0

  Caller->>Processor: Protect(plainApdu)
  Processor->>Keys: GetKey(encryption/authentication role)
  Keys-->>Processor: key bytes
  Processor->>Counters: NextLocal()
  Counters-->>Processor: invocation counter
  Processor->>GCM: Seal(systemTitle, counter, securityControl, plainApdu)
  GCM-->>Processor: cipher text and tag
  Processor-->>Caller: protected APDU bytes
```

## 6. HLS GMAC Flow

```mermaid
sequenceDiagram
  participant Association
  participant HLS as HlsGmacAuthenticator
  participant Random as IRandomSource
  participant Keys as IKeyStore
  participant Counters as IInvocationCounterStore

  Association->>HLS: BuildChallenge()
  HLS->>Random: Fill(challenge)
  Random-->>HLS: challenge bytes
  HLS-->>Association: challenge

  Association->>HLS: BuildResponse(peerChallenge)
  HLS->>Keys: GetKey(authentication)
  HLS->>Counters: NextLocal()
  HLS-->>Association: GMAC response
```

## 7. Error Model

The layer converts all validation and cryptographic failures to
`SecurityStatus`. Runtime exceptions are not part of the public API.

Key material and plaintext APDUs must not be emitted through status names,
logging, or diagnostic strings.

## 8. Protected APDU Body

`CipheredApduProcessor` owns only the security body:

```text
security-control(1) || invocation-counter(4, big endian) ||
ciphertext(N) || authentication-tag(16)
```

For Suite 0 `AuthenticatedAndEncrypted`, the nonce is
`system-title(8) || invocation-counter(4)`. Protection uses the local system
title and `NextLocal`; unprotection uses the remote system title and accepts
the remote invocation counter only after successful authentication.

## 9. Test Strategy

Tests shall focus on:

- enum and validation behavior;
- key length validation;
- invocation counter monotonicity;
- deterministic challenge generation with fake random source;
- Suite 0 AES-GCM vectors;
- protect/unprotect round trip;
- replay rejection.
