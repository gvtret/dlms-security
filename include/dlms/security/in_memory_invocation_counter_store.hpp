#pragma once

#include "dlms/security/invocation_counter_store.hpp"

namespace dlms {
namespace security {

class InMemoryInvocationCounterStore : public IInvocationCounterStore
{
public:
  InMemoryInvocationCounterStore();

  void SetLocalCounter(std::uint32_t invocationCounter);
  void SetHighestRemoteCounter(std::uint32_t invocationCounter);

  SecurityStatus NextLocal(std::uint32_t& invocationCounter);
  SecurityStatus ValidateRemote(std::uint32_t invocationCounter);

private:
  std::uint32_t nextLocal_;
  std::uint32_t highestRemote_;
};

} // namespace security
} // namespace dlms
