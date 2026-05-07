#pragma once

#include "dlms/security/security_status.hpp"

#include <cstdint>

namespace dlms {
namespace security {

class IInvocationCounterStore
{
public:
  virtual ~IInvocationCounterStore() {}

  virtual SecurityStatus NextLocal(
    std::uint32_t& invocationCounter) = 0;

  virtual SecurityStatus ValidateRemote(
    std::uint32_t invocationCounter) = 0;
};

} // namespace security
} // namespace dlms
