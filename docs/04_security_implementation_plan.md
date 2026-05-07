# 04. Security Implementation Plan

## Phase 0. Documentation

Deliverables:

- requirements;
- public API contract;
- architecture diagrams;
- test plan;
- implementation plan;
- minimal CMake interface target.

Commit message:

```text
docs(security): define security layer contract
```

## Phase 1. Status And Types

Deliverables:

- `SecurityStatus`;
- status name helper;
- security suite, policy, control, role, and key-role enums;
- byte-view and key structs;
- context validation helpers;
- unit tests.

Commit message:

```text
feat(security): add status and core types
```

## Phase 2. Key And Counter Interfaces

Deliverables:

- `IKeyStore`;
- `IInvocationCounterStore`;
- in-memory test implementations;
- key length validation;
- monotonic counter behavior;
- unit tests.

Commit message:

```text
feat(security): add key and counter interfaces
```

## Phase 3. Suite 0 AES-GCM Engine

Deliverables:

- Suite 0 AES-GCM seal/open API;
- fixed test vectors;
- authentication tag validation;
- invalid input and key tests.

Commit message:

```text
feat(security): add suite 0 aes gcm engine
```

## Phase 4. Ciphered APDU Processor

Deliverables:

- `CipheredApduProcessor`;
- protect/unprotect opaque APDU bytes;
- security header construction and parsing;
- invocation counter integration;
- replay rejection tests.

Commit message:

```text
feat(security): protect ciphered apdus
```

## Phase 5. HLS GMAC Plumbing

Deliverables:

- `IRandomSource`;
- `HlsGmacAuthenticator`;
- deterministic challenge tests;
- fixed HLS GMAC response vector tests.

Commit message:

```text
feat(security): add hls gmac authenticator
```

## Phase 6. Root Integration

Deliverables:

- root submodule entry;
- root CMake wiring;
- no-security regression check with security layer present;
- first ciphered GET integration test once `dlms-xdlms` and `dlms-server`
  consume the security API.

Commit message:

```text
test: cover security layer integration
```
