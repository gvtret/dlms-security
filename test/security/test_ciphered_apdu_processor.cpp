#include "dlms/security/ciphered_apdu_processor.hpp"

#include "dlms/security/in_memory_invocation_counter_store.hpp"
#include "dlms/security/in_memory_key_store.hpp"

#include <gtest/gtest.h>

namespace {

dlms::security::SecurityKey MakeKey(
  dlms::security::SecurityKeyRole role,
  std::uint8_t seed)
{
  dlms::security::SecurityKey key = dlms::security::EmptySecurityKey(role);
  key.size = 16u;
  for (std::size_t i = 0u; i < key.size; ++i) {
    key.bytes[i] = static_cast<std::uint8_t>(seed + i);
  }
  return key;
}

dlms::security::SecurityContext MakeContext(
  dlms::security::SecurityRole role)
{
  dlms::security::SecurityContext context =
    dlms::security::EmptySecurityContext();
  context.policy = dlms::security::SecurityPolicy::AuthenticatedAndEncrypted;
  context.role = role;
  context.clientSap = 16u;
  context.serverSap = 1u;

  const std::uint8_t clientTitle[8] =
    {0x4du, 0x4du, 0x4du, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u};
  const std::uint8_t serverTitle[8] =
    {0x4du, 0x45u, 0x54u, 0x00u, 0x00u, 0x00u, 0x00u, 0x02u};

  for (std::size_t i = 0u; i < 8u; ++i) {
    if (role == dlms::security::SecurityRole::Client) {
      context.localSystemTitle[i] = clientTitle[i];
      context.remoteSystemTitle[i] = serverTitle[i];
    } else {
      context.localSystemTitle[i] = serverTitle[i];
      context.remoteSystemTitle[i] = clientTitle[i];
    }
  }

  return context;
}

dlms::security::SecurityByteView ViewOf(
  const std::vector<std::uint8_t>& data)
{
  dlms::security::SecurityByteView view;
  view.data = data.empty() ? 0 : &data[0];
  view.size = data.size();
  return view;
}

void InstallKeys(dlms::security::InMemoryKeyStore& keys)
{
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    keys.SetKey(
      MakeKey(
        dlms::security::SecurityKeyRole::GlobalUnicastEncryption,
        0x10u)));
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    keys.SetKey(
      MakeKey(
        dlms::security::SecurityKeyRole::Authentication,
        0x80u)));
}

} // namespace

TEST(CipheredApduProcessor, ProtectsAndUnprotectsOpaqueApdu)
{
  dlms::security::InMemoryKeyStore keys;
  InstallKeys(keys);

  dlms::security::InMemoryInvocationCounterStore clientCounters;
  clientCounters.SetLocalCounter(1u);
  dlms::security::InMemoryInvocationCounterStore serverCounters;

  const dlms::security::SecurityContext clientContext =
    MakeContext(dlms::security::SecurityRole::Client);
  const dlms::security::SecurityContext serverContext =
    MakeContext(dlms::security::SecurityRole::Server);

  dlms::security::CipheredApduProcessor client(
    clientContext,
    keys,
    clientCounters);
  dlms::security::CipheredApduProcessor server(
    serverContext,
    keys,
    serverCounters);

  const std::uint8_t raw[] =
    {0xc0u, 0x01u, 0xc1u, 0x00u, 0x01u, 0x00u, 0x00u, 0xffu};
  dlms::security::SecurityByteView plain;
  plain.data = raw;
  plain.size = sizeof(raw);

  std::vector<std::uint8_t> protectedApdu;
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    client.Protect(plain, protectedApdu));

  ASSERT_GE(protectedApdu.size(), 1u + 4u + 16u);
  EXPECT_EQ(0x30u, protectedApdu[0]);
  EXPECT_EQ(0x00u, protectedApdu[1]);
  EXPECT_EQ(0x00u, protectedApdu[2]);
  EXPECT_EQ(0x00u, protectedApdu[3]);
  EXPECT_EQ(0x01u, protectedApdu[4]);

  std::vector<std::uint8_t> unprotectedApdu;
  EXPECT_EQ(
    dlms::security::SecurityStatus::Ok,
    server.Unprotect(ViewOf(protectedApdu), unprotectedApdu));
  ASSERT_EQ(sizeof(raw), unprotectedApdu.size());
  for (std::size_t i = 0u; i < sizeof(raw); ++i) {
    EXPECT_EQ(raw[i], unprotectedApdu[i]);
  }
}

TEST(CipheredApduProcessor, RejectsReplayAfterSuccessfulUnprotect)
{
  dlms::security::InMemoryKeyStore keys;
  InstallKeys(keys);

  dlms::security::InMemoryInvocationCounterStore clientCounters;
  clientCounters.SetLocalCounter(7u);
  dlms::security::InMemoryInvocationCounterStore serverCounters;

  dlms::security::CipheredApduProcessor client(
    MakeContext(dlms::security::SecurityRole::Client),
    keys,
    clientCounters);
  dlms::security::CipheredApduProcessor server(
    MakeContext(dlms::security::SecurityRole::Server),
    keys,
    serverCounters);

  const std::uint8_t raw[] = {0x01u, 0x02u, 0x03u};
  dlms::security::SecurityByteView plain;
  plain.data = raw;
  plain.size = sizeof(raw);

  std::vector<std::uint8_t> protectedApdu;
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    client.Protect(plain, protectedApdu));

  std::vector<std::uint8_t> unprotectedApdu;
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    server.Unprotect(ViewOf(protectedApdu), unprotectedApdu));
  EXPECT_EQ(
    dlms::security::SecurityStatus::ReplayDetected,
    server.Unprotect(ViewOf(protectedApdu), unprotectedApdu));
  EXPECT_TRUE(unprotectedApdu.empty());
}

TEST(CipheredApduProcessor, RejectsTamperedTagWithoutAdvancingReplayState)
{
  dlms::security::InMemoryKeyStore keys;
  InstallKeys(keys);

  dlms::security::InMemoryInvocationCounterStore clientCounters;
  clientCounters.SetLocalCounter(9u);
  dlms::security::InMemoryInvocationCounterStore serverCounters;

  dlms::security::CipheredApduProcessor client(
    MakeContext(dlms::security::SecurityRole::Client),
    keys,
    clientCounters);
  dlms::security::CipheredApduProcessor server(
    MakeContext(dlms::security::SecurityRole::Server),
    keys,
    serverCounters);

  const std::uint8_t raw[] = {0x11u, 0x22u, 0x33u, 0x44u};
  dlms::security::SecurityByteView plain;
  plain.data = raw;
  plain.size = sizeof(raw);

  std::vector<std::uint8_t> protectedApdu;
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    client.Protect(plain, protectedApdu));

  std::vector<std::uint8_t> tampered = protectedApdu;
  tampered[tampered.size() - 1u] ^= 0x01u;

  std::vector<std::uint8_t> unprotectedApdu;
  EXPECT_EQ(
    dlms::security::SecurityStatus::DecipherFailed,
    server.Unprotect(ViewOf(tampered), unprotectedApdu));
  EXPECT_EQ(
    dlms::security::SecurityStatus::Ok,
    server.Unprotect(ViewOf(protectedApdu), unprotectedApdu));
}

TEST(CipheredApduProcessor, PassesThroughWhenPolicyIsNone)
{
  dlms::security::InMemoryKeyStore keys;
  dlms::security::InMemoryInvocationCounterStore counters;
  dlms::security::SecurityContext context =
    dlms::security::EmptySecurityContext();
  context.clientSap = 16u;
  context.serverSap = 1u;

  dlms::security::CipheredApduProcessor processor(context, keys, counters);

  const std::uint8_t raw[] = {0xdeu, 0xadu, 0xbeu, 0xefu};
  dlms::security::SecurityByteView plain;
  plain.data = raw;
  plain.size = sizeof(raw);

  std::vector<std::uint8_t> protectedApdu;
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    processor.Protect(plain, protectedApdu));
  EXPECT_EQ(sizeof(raw), protectedApdu.size());

  std::vector<std::uint8_t> unprotectedApdu;
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    processor.Unprotect(ViewOf(protectedApdu), unprotectedApdu));
  EXPECT_EQ(protectedApdu, unprotectedApdu);
}

TEST(CipheredApduProcessor, RejectsUnsupportedPartialPolicies)
{
  dlms::security::InMemoryKeyStore keys;
  dlms::security::InMemoryInvocationCounterStore counters;
  dlms::security::SecurityContext context =
    MakeContext(dlms::security::SecurityRole::Client);
  context.policy = dlms::security::SecurityPolicy::Authenticated;

  dlms::security::CipheredApduProcessor processor(context, keys, counters);

  const std::uint8_t raw[] = {0x01u};
  dlms::security::SecurityByteView plain;
  plain.data = raw;
  plain.size = sizeof(raw);

  std::vector<std::uint8_t> protectedApdu;
  EXPECT_EQ(
    dlms::security::SecurityStatus::UnsupportedFeature,
    processor.Protect(plain, protectedApdu));
}

TEST(CipheredApduProcessor, RejectsMalformedProtectedApdu)
{
  dlms::security::InMemoryKeyStore keys;
  InstallKeys(keys);
  dlms::security::InMemoryInvocationCounterStore counters;
  dlms::security::CipheredApduProcessor processor(
    MakeContext(dlms::security::SecurityRole::Server),
    keys,
    counters);

  const std::uint8_t malformed[] = {0x30u, 0x00u, 0x00u};
  dlms::security::SecurityByteView protectedApdu;
  protectedApdu.data = malformed;
  protectedApdu.size = sizeof(malformed);

  std::vector<std::uint8_t> plain;
  EXPECT_EQ(
    dlms::security::SecurityStatus::InvalidArgument,
    processor.Unprotect(protectedApdu, plain));
}
