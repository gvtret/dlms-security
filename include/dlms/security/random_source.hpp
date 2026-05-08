#pragma once

#include "dlms/security/security_status.hpp"

#include <cstddef>
#include <cstdint>

namespace dlms {
namespace security {

class IRandomSource
{
public:
  virtual ~IRandomSource() {}

  virtual SecurityStatus Fill(
    std::uint8_t* output,
    std::size_t outputSize) = 0;
};

} // namespace security
} // namespace dlms
