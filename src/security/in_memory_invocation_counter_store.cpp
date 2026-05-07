#include "dlms/security/in_memory_invocation_counter_store.hpp"

#include <limits>

namespace dlms {
namespace security {

InMemoryInvocationCounterStore::InMemoryInvocationCounterStore()
  : nextLocal_(1u)
  , highestRemote_(0u)
{
}

void InMemoryInvocationCounterStore::SetLocalCounter(
  std::uint32_t invocationCounter)
{
  nextLocal_ = invocationCounter;
}

void InMemoryInvocationCounterStore::SetHighestRemoteCounter(
  std::uint32_t invocationCounter)
{
  highestRemote_ = invocationCounter;
}

SecurityStatus InMemoryInvocationCounterStore::NextLocal(
  std::uint32_t& invocationCounter)
{
  if (nextLocal_ == std::numeric_limits<std::uint32_t>::max()) {
    return SecurityStatus::InvocationCounterExhausted;
  }

  invocationCounter = nextLocal_;
  ++nextLocal_;
  return SecurityStatus::Ok;
}

SecurityStatus InMemoryInvocationCounterStore::ValidateRemote(
  std::uint32_t invocationCounter)
{
  if (invocationCounter == 0u) {
    return SecurityStatus::InvalidInvocationCounter;
  }

  if (invocationCounter <= highestRemote_) {
    return SecurityStatus::ReplayDetected;
  }

  highestRemote_ = invocationCounter;
  return SecurityStatus::Ok;
}

} // namespace security
} // namespace dlms
