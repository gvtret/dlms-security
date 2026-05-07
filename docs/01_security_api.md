# 01. Security API

## 1. API Shape

The public C++ API is split into small protocol concepts:

- status and name helpers;
- security suite and policy enums;
- security context;
- key-store interface;
- invocation-counter interface;
- random-source interface;
- ciphered APDU processor;
- authentication helpers.

Phase 0 defines the contract only. Header implementation begins in Phase 1.

## 2. Status Model

Planned status enum:

```cpp
enum class SecurityStatus
{
  Ok,
  InvalidArgument,
  InvalidContext,
  UnsupportedFeature,
  MissingKey,
  InvalidKeyLength,
  InvalidSystemTitle,
  InvalidInvocationCounter,
  InvocationCounterExhausted,
  ReplayDetected,
  AuthenticationFailed,
  CipherFailed,
  DecipherFailed,
  OutputBufferTooSmall,
  InternalError
};
```

All runtime functions return `SecurityStatus`.

## 3. Security Context

`SecurityContext` describes one security association view:

```cpp
struct SecurityContext
{
  SecuritySuite suite;
  SecurityPolicy policy;
  SecurityControl securityControl;
  SecurityRole role;
  std::uint16_t clientSap;
  std::uint16_t serverSap;
  std::uint8_t localSystemTitle[8];
  std::uint8_t remoteSystemTitle[8];
};
```

The context is immutable during a single APDU protect/unprotect operation.

## 4. Key Store

```cpp
class IKeyStore
{
public:
  virtual ~IKeyStore() {}

  virtual SecurityStatus GetKey(
    SecurityKeyRole role,
    SecurityKey& output) const = 0;
};
```

`SecurityKey` shall own fixed-size key bytes and an explicit key length.

## 5. Invocation Counters

```cpp
class IInvocationCounterStore
{
public:
  virtual ~IInvocationCounterStore() {}

  virtual SecurityStatus NextLocal(
    std::uint32_t& invocationCounter) = 0;

  virtual SecurityStatus ValidateRemote(
    std::uint32_t invocationCounter) = 0;
};
```

## 6. Random Source

```cpp
class IRandomSource
{
public:
  virtual ~IRandomSource() {}

  virtual SecurityStatus Fill(
    std::uint8_t* output,
    std::size_t outputSize) = 0;
};
```

The layer shall provide deterministic fake implementations for tests only.

## 7. Ciphered APDU Processor

```cpp
class CipheredApduProcessor
{
public:
  CipheredApduProcessor(
    const SecurityContext& context,
    const IKeyStore& keys,
    IInvocationCounterStore& counters);

  SecurityStatus Protect(
    SecurityByteView plainApdu,
    std::vector<std::uint8_t>& protectedApdu);

  SecurityStatus Unprotect(
    SecurityByteView protectedApdu,
    std::vector<std::uint8_t>& plainApdu);
};
```

The processor treats APDUs as opaque bytes.

## 8. HLS GMAC Authenticator

```cpp
class HlsGmacAuthenticator
{
public:
  HlsGmacAuthenticator(
    const SecurityContext& context,
    const IKeyStore& keys,
    IInvocationCounterStore& counters,
    IRandomSource& random);

  SecurityStatus BuildChallenge(std::vector<std::uint8_t>& challenge);

  SecurityStatus BuildResponse(
    SecurityByteView challenge,
    std::vector<std::uint8_t>& response);

  SecurityStatus VerifyResponse(
    SecurityByteView challenge,
    SecurityByteView response);
};
```

## 9. C ABI

C ABI is explicitly deferred. The first implementation shall stabilize the C++
API and test vectors before adding C wrappers.
