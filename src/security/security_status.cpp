#include "dlms/security/security_status.hpp"

namespace dlms {
namespace security {

const char* SecurityStatusName(SecurityStatus status)
{
  switch (status) {
  case SecurityStatus::Ok:
    return "Ok";
  case SecurityStatus::InvalidArgument:
    return "InvalidArgument";
  case SecurityStatus::InvalidContext:
    return "InvalidContext";
  case SecurityStatus::UnsupportedFeature:
    return "UnsupportedFeature";
  case SecurityStatus::MissingKey:
    return "MissingKey";
  case SecurityStatus::InvalidKeyLength:
    return "InvalidKeyLength";
  case SecurityStatus::InvalidSystemTitle:
    return "InvalidSystemTitle";
  case SecurityStatus::InvalidInvocationCounter:
    return "InvalidInvocationCounter";
  case SecurityStatus::InvocationCounterExhausted:
    return "InvocationCounterExhausted";
  case SecurityStatus::ReplayDetected:
    return "ReplayDetected";
  case SecurityStatus::AuthenticationFailed:
    return "AuthenticationFailed";
  case SecurityStatus::CipherFailed:
    return "CipherFailed";
  case SecurityStatus::DecipherFailed:
    return "DecipherFailed";
  case SecurityStatus::OutputBufferTooSmall:
    return "OutputBufferTooSmall";
  case SecurityStatus::InternalError:
    return "InternalError";
  }

  return "Unknown";
}

} // namespace security
} // namespace dlms
