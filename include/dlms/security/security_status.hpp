#pragma once

namespace dlms {
namespace security {

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

const char* SecurityStatusName(SecurityStatus status);

} // namespace security
} // namespace dlms
