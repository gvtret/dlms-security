#pragma once

#include "dlms/security/random_source.hpp"
#include "dlms/security/security_types.hpp"

#include <vector>

namespace dlms {
namespace security {

class HlsHighAuthenticator
{
public:
  static const std::size_t kChallengeSize = 16u;

  HlsHighAuthenticator(
    SecurityByteView password,
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
  std::vector<std::uint8_t> password_;
  IRandomSource& random_;
};

} // namespace security
} // namespace dlms
