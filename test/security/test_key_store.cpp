#include "dlms/security/in_memory_key_store.hpp"

#include <gtest/gtest.h>

namespace {

dlms::security::SecurityKey MakeKey(
  dlms::security::SecurityKeyRole role,
  std::size_t size)
{
  dlms::security::SecurityKey key = dlms::security::EmptySecurityKey(role);
  key.size = size;
  for (std::size_t i = 0u; i < size; ++i) {
    key.bytes[i] = static_cast<std::uint8_t>(i + 1u);
  }
  return key;
}

} // namespace

TEST(InMemoryKeyStore, ReportsMissingKey)
{
  dlms::security::InMemoryKeyStore store;
  dlms::security::SecurityKey key =
    dlms::security::EmptySecurityKey(
      dlms::security::SecurityKeyRole::Authentication);

  EXPECT_EQ(dlms::security::SecurityStatus::MissingKey,
            store.GetKey(
              dlms::security::SecurityKeyRole::Authentication,
              key));
  EXPECT_EQ(0u, key.size);
}

TEST(InMemoryKeyStore, StoresKeysByRole)
{
  dlms::security::InMemoryKeyStore store;
  const dlms::security::SecurityKey encryptionKey =
    MakeKey(
      dlms::security::SecurityKeyRole::GlobalUnicastEncryption,
      16u);

  ASSERT_EQ(dlms::security::SecurityStatus::Ok,
            store.SetKey(encryptionKey));

  dlms::security::SecurityKey found =
    dlms::security::EmptySecurityKey(
      dlms::security::SecurityKeyRole::GlobalUnicastEncryption);
  EXPECT_EQ(dlms::security::SecurityStatus::Ok,
            store.GetKey(
              dlms::security::SecurityKeyRole::GlobalUnicastEncryption,
              found));
  EXPECT_EQ(encryptionKey.role, found.role);
  EXPECT_EQ(encryptionKey.size, found.size);
  EXPECT_EQ(encryptionKey.bytes[0], found.bytes[0]);
  EXPECT_EQ(encryptionKey.bytes[15], found.bytes[15]);
}

TEST(InMemoryKeyStore, RejectsEmptyKey)
{
  dlms::security::InMemoryKeyStore store;

  EXPECT_EQ(dlms::security::SecurityStatus::InvalidKeyLength,
            store.SetKey(
              dlms::security::EmptySecurityKey(
                dlms::security::SecurityKeyRole::Authentication)));
}

TEST(InMemoryKeyStore, ClearRemovesKeys)
{
  dlms::security::InMemoryKeyStore store;
  ASSERT_EQ(dlms::security::SecurityStatus::Ok,
            store.SetKey(
              MakeKey(
                dlms::security::SecurityKeyRole::Authentication,
                16u)));

  store.Clear();

  dlms::security::SecurityKey found =
    dlms::security::EmptySecurityKey(
      dlms::security::SecurityKeyRole::Authentication);
  EXPECT_EQ(dlms::security::SecurityStatus::MissingKey,
            store.GetKey(
              dlms::security::SecurityKeyRole::Authentication,
              found));
}
