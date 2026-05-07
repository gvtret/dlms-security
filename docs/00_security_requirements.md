# 00. Security Requirements

## 1. Scope

`dlms-security` provides DLMS/COSEM application-layer security primitives and
policies used by association and xDLMS service layers.

The layer is based on IEC 62056-5-3 / Green Book security concepts:

- security suites;
- security policy;
- security control byte;
- system titles;
- invocation counters;
- symmetric key roles;
- AES-GCM authenticated encryption;
- low-level and high-level authentication plumbing.

Phase 0 is documentation only. Runtime implementation starts in Phase 1.

## 2. Fixed Design Decisions

| Area | Decision |
|---|---|
| Language | C++11 |
| Build system | CMake 3.16+ |
| Error handling | Status codes only |
| Exceptions | Not used in public/runtime API paths |
| First suite | Security Suite 0, AES-GCM-128 |
| First authentication modes | None, LLS, HLS GMAC plumbing |
| Persistent storage | Out of scope; injected interfaces only |
| Transport TLS | Out of scope |
| COSEM access model | Out of scope |
| C ABI | Deferred until C++ API stabilizes |
| Tests | GoogleTest |

## 3. Layering Rules

`dlms-security` may be consumed by:

- `dlms-association`;
- `dlms-xdlms`;
- `dlms-cosem`;
- `dlms-server`;
- `dlms-client`.

`dlms-security` must not depend on:

- `dlms-transport`;
- `dlms-profile`;
- `dlms-association`;
- `dlms-xdlms`;
- `dlms-cosem`;
- `dlms-server`;
- `dlms-client`.

Allowed future dependency:

- `dlms-common`, if byte-view and status helpers are extracted.

## 4. Security Suite Requirements

The first implementation shall support Suite 0 only:

```text
Security Suite 0 = AES-GCM-128
Key length       = 128 bits
System title     = 8 octets
Invocation ctr   = 32-bit unsigned value encoded in security headers
```

Suite 1 and Suite 2 shall be represented in enums and validation, but runtime
cryptographic execution can return `UnsupportedFeature` until implemented.

## 5. Key Requirements

The API shall distinguish key roles instead of accepting anonymous byte arrays:

- global unicast encryption key;
- global broadcast encryption key;
- authentication key;
- key encryption key;
- dedicated key.

The layer shall retrieve keys through an injected key-store interface.

The layer shall not:

- persist keys;
- log key bytes;
- derive deployment-specific keys;
- read keys from files or environment variables.

## 6. Invocation Counter Requirements

The invocation counter policy shall:

- provide the next local invocation counter for protected outbound APDUs;
- validate inbound remote invocation counters;
- reject replayed or stale counters;
- surface counter exhaustion as a status code.

Persistent counter storage is out of scope. The layer owns only the interface
and in-memory test implementation.

## 7. APDU Protection Requirements

The protection API shall support:

- authenticated only;
- encrypted only, if allowed by policy;
- authenticated and encrypted;
- global ciphering security control fields;
- service-specific ciphered APDU payloads as opaque bytes.

The layer shall not parse GET, SET, ACTION, or ACSE semantics. Callers provide
plain APDU bytes and receive protected APDU bytes.

## 8. Authentication Requirements

LLS:

- store and expose credential bytes through association-facing options;
- do not hash or transform LLS password unless a later spec-specific mode
  requires it.

HLS GMAC:

- generate deterministic test challenges through an injected random source;
- build HLS GMAC challenge responses from security context, key material, and
  invocation counter;
- verify peer challenge responses;
- keep MD5/SHA1 HLS mechanisms out of the first implementation.

## 9. Out Of Scope For v1

- Security Suite 1 and Suite 2 execution;
- ECDSA;
- ECDH key agreement;
- AES key wrap;
- compression;
- persistent key vaults;
- TLS;
- COSEM Security Setup object implementation;
- HDLC authentication;
- multi-client session storage.

## 10. Acceptance Criteria

Phase 1 starts only after these documents exist:

- requirements;
- public API contract;
- architecture with diagrams;
- test plan;
- implementation plan;
- minimal CMake target.

Runtime phases must be accepted by focused unit tests and later root integration
tests, not by live meter-only testing.
