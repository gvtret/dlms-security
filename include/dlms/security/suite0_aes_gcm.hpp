#pragma once

#include "dlms/security/security_types.hpp"

#include <vector>

namespace dlms {
namespace security {

struct AesGcmParameters
{
  SecurityByteView nonce;
  SecurityByteView additionalAuthenticatedData;
  SecurityByteView input;
};

class Suite0AesGcm
{
public:
  static const std::size_t kKeySize = 16u;
  static const std::size_t kNonceSize = 12u;
  static const std::size_t kTagSize = 16u;

  SecurityStatus Seal(
    const SecurityKey& key,
    const AesGcmParameters& parameters,
    std::vector<std::uint8_t>& cipherText,
    std::uint8_t tag[kTagSize]) const;

  SecurityStatus Open(
    const SecurityKey& key,
    const AesGcmParameters& parameters,
    const std::uint8_t tag[kTagSize],
    std::vector<std::uint8_t>& plainText) const;
};

} // namespace security
} // namespace dlms
