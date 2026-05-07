#pragma once

#include "dlms/security/security_status.hpp"

#include <cstddef>
#include <cstdint>

namespace dlms {
namespace security {

enum class SecuritySuite
{
  Suite0,
  Suite1,
  Suite2
};

enum class SecurityRole
{
  Client,
  Server
};

enum class SecurityKeyRole
{
  GlobalUnicastEncryption,
  GlobalBroadcastEncryption,
  Authentication,
  KeyEncryption,
  Dedicated
};

enum class SecurityPolicy
{
  None,
  Authenticated,
  Encrypted,
  AuthenticatedAndEncrypted
};

struct SecurityByteView
{
  const std::uint8_t* data;
  std::size_t size;
};

struct SecurityKey
{
  SecurityKeyRole role;
  std::uint8_t bytes[32];
  std::size_t size;
};

struct SecurityContext
{
  SecuritySuite suite;
  SecurityPolicy policy;
  SecurityRole role;
  std::uint16_t clientSap;
  std::uint16_t serverSap;
  std::uint8_t localSystemTitle[8];
  std::uint8_t remoteSystemTitle[8];
};

SecurityKey EmptySecurityKey(SecurityKeyRole role);
SecurityContext EmptySecurityContext();

bool IsValidSecurityByteView(SecurityByteView view);
bool IsValidSystemTitle(const std::uint8_t systemTitle[8]);
std::size_t RequiredKeySize(SecuritySuite suite);

SecurityStatus ValidateSecurityKey(
  SecuritySuite suite,
  const SecurityKey& key);

SecurityStatus ValidateSecurityContext(const SecurityContext& context);

} // namespace security
} // namespace dlms
