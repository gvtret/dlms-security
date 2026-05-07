#pragma once

#include "dlms/security/key_store.hpp"

#include <map>

namespace dlms {
namespace security {

class InMemoryKeyStore : public IKeyStore
{
public:
  SecurityStatus SetKey(const SecurityKey& key);
  void Clear();

  SecurityStatus GetKey(
    SecurityKeyRole role,
    SecurityKey& output) const;

private:
  std::map<SecurityKeyRole, SecurityKey> keys_;
};

} // namespace security
} // namespace dlms
