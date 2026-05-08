#pragma once

#include "dlms/security/invocation_counter_store.hpp"
#include "dlms/security/key_store.hpp"
#include "dlms/security/random_source.hpp"
#include "dlms/security/security_types.hpp"

#include <vector>

namespace dlms {
namespace security {

class HlsGmacAuthenticator
{
public:
  static const std::size_t kChallengeSize = 16u;
  static const std::size_t kResponseTagSize = 16u;

  HlsGmacAuthenticator(
    const SecurityContext& context,
    const IKeyStore& keys,
    IInvocationCounterStore& counters,
    IRandomSource& random);

  SecurityStatus BuildChallenge(
    std::vector<std::uint8_t>& challenge) const;

  SecurityStatus BuildResponse(
    SecurityByteView challenge,
    std::vector<std::uint8_t>& response) const;

  SecurityStatus VerifyResponse(
    SecurityByteView challenge,
    SecurityByteView response) const;

private:
  const SecurityContext& context_;
  const IKeyStore& keys_;
  IInvocationCounterStore& counters_;
  IRandomSource& random_;
};

} // namespace security
} // namespace dlms
