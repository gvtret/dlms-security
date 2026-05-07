# 03. Security Test Plan

## 1. Scope

Tests are split into repository-local unit tests and root integration tests.

Repository-local tests prove security primitives and policy behavior. Root tests
prove that association, xDLMS, client, and server layers call the security layer
correctly.

## 2. Unit Test Groups

### Status And Types

- status names are stable;
- default context is invalid until required fields are set;
- Suite 0 validates 128-bit keys;
- Suite 1/2 are represented but rejected as unsupported in v1.

### Key Store

- missing key returns `MissingKey`;
- wrong key size returns `InvalidKeyLength`;
- key roles are not conflated.

### Invocation Counters

- `NextLocal` returns monotonic values;
- counter exhaustion is reported;
- repeated remote counter is rejected;
- lower remote counter is rejected;
- higher remote counter is accepted and stored.

### Random Source

- deterministic fake source fills exactly requested bytes;
- invalid output buffer is rejected.

### Ciphered APDU Processor

- rejects invalid context;
- rejects missing keys;
- protects and unprotects a Suite 0 APDU vector;
- rejects modified authentication tag;
- rejects replayed invocation counter;
- preserves opaque APDU payload bytes.

### HLS GMAC

- builds deterministic challenge with fake random source;
- builds expected GMAC response from a fixed vector;
- verifies expected response;
- rejects modified response.

## 3. Root Integration Tests

Initial root acceptance tests:

- no-security behavior remains unchanged when `dlms-security` is present;
- LLS association passes credential bytes through association options;
- HLS GMAC challenge-response path is exercised through association once the
  association layer consumes the security API;
- ciphered GET round trip covers `dlms-security`, `dlms-xdlms`, and
  `dlms-server`.

## 4. Live Meter Tests

Live meter tests are not unit-test acceptance criteria.

The available WRAPPER meter can be used later for manual validation:

- public client 16 with security None;
- client 32 with LLS password;
- client 48 with HLS high password.

Live tests must not be required for CI.

## 5. Verification Commands

Expected local verification shape:

```text
cmake -S . -B build-mingw64
cmake --build build-mingw64
ctest --test-dir build-mingw64 --output-on-failure
```

When run from PowerShell with MSYS2 MinGW tools, `C:\msys\mingw64\bin` must be
present in `PATH` before invoking compiler, CMake, or tests.
