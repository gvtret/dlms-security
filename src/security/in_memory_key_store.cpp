#include "dlms/security/in_memory_key_store.hpp"

namespace dlms {
namespace security {

SecurityStatus InMemoryKeyStore::SetKey(const SecurityKey& key)
{
  if (key.size == 0u || key.size > sizeof(key.bytes)) {
    return SecurityStatus::InvalidKeyLength;
  }

  keys_[key.role] = key;
  return SecurityStatus::Ok;
}

void InMemoryKeyStore::Clear()
{
  keys_.clear();
}

SecurityStatus InMemoryKeyStore::GetKey(
  SecurityKeyRole role,
  SecurityKey& output) const
{
  const std::map<SecurityKeyRole, SecurityKey>::const_iterator found =
    keys_.find(role);
  if (found == keys_.end()) {
    output = EmptySecurityKey(role);
    return SecurityStatus::MissingKey;
  }

  output = found->second;
  return SecurityStatus::Ok;
}

} // namespace security
} // namespace dlms
