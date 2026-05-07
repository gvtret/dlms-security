#include "dlms/security/security_types.hpp"

namespace dlms {
namespace security {

SecurityKey EmptySecurityKey(SecurityKeyRole role)
{
  SecurityKey key;
  key.role = role;
  key.size = 0u;
  for (std::size_t i = 0u; i < sizeof(key.bytes); ++i) {
    key.bytes[i] = 0u;
  }
  return key;
}

SecurityContext EmptySecurityContext()
{
  SecurityContext context;
  context.suite = SecuritySuite::Suite0;
  context.policy = SecurityPolicy::None;
  context.role = SecurityRole::Client;
  context.clientSap = 0u;
  context.serverSap = 0u;
  for (std::size_t i = 0u; i < 8u; ++i) {
    context.localSystemTitle[i] = 0u;
    context.remoteSystemTitle[i] = 0u;
  }
  return context;
}

bool IsValidSecurityByteView(SecurityByteView view)
{
  return view.size == 0u || view.data != 0;
}

bool IsValidSystemTitle(const std::uint8_t systemTitle[8])
{
  if (systemTitle == 0) {
    return false;
  }

  for (std::size_t i = 0u; i < 8u; ++i) {
    if (systemTitle[i] != 0u) {
      return true;
    }
  }
  return false;
}

std::size_t RequiredKeySize(SecuritySuite suite)
{
  switch (suite) {
  case SecuritySuite::Suite0:
  case SecuritySuite::Suite1:
    return 16u;
  case SecuritySuite::Suite2:
    return 32u;
  }

  return 0u;
}

SecurityStatus ValidateSecurityKey(
  SecuritySuite suite,
  const SecurityKey& key)
{
  const std::size_t requiredSize = RequiredKeySize(suite);
  if (requiredSize == 0u) {
    return SecurityStatus::UnsupportedFeature;
  }

  if (key.size == 0u) {
    return SecurityStatus::MissingKey;
  }

  if (key.size != requiredSize) {
    return SecurityStatus::InvalidKeyLength;
  }

  return SecurityStatus::Ok;
}

SecurityStatus ValidateSecurityContext(const SecurityContext& context)
{
  if (context.suite != SecuritySuite::Suite0) {
    return SecurityStatus::UnsupportedFeature;
  }

  if (context.clientSap == 0u || context.serverSap == 0u) {
    return SecurityStatus::InvalidContext;
  }

  if (context.policy == SecurityPolicy::None) {
    return SecurityStatus::Ok;
  }

  if (!IsValidSystemTitle(context.localSystemTitle) ||
      !IsValidSystemTitle(context.remoteSystemTitle)) {
    return SecurityStatus::InvalidSystemTitle;
  }

  return SecurityStatus::Ok;
}

} // namespace security
} // namespace dlms
