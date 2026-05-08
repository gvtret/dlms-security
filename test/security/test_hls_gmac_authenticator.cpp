#include "dlms/security/hls_gmac_authenticator.hpp"

#include "dlms/security/in_memory_invocation_counter_store.hpp"
#include "dlms/security/in_memory_key_store.hpp"

#include <gtest/gtest.h>

namespace {

class FixedRandomSource : public dlms::security::IRandomSource
{
public:
  explicit FixedRandomSource(std::uint8_t seed)
    : seed_(seed)
  {
  }

  dlms::security::SecurityStatus Fill(
    std::uint8_t* output,
    std::size_t outputSize)
  {
    if (output == 0 && outputSize != 0u) {
      return dlms::security::SecurityStatus::InvalidArgument;
    }

    for (std::size_t i = 0u; i < outputSize; ++i) {
      output[i] = static_cast<std::uint8_t>(seed_ + i);
    }
    return dlms::security::SecurityStatus::Ok;
  }

private:
  std::uint8_t seed_;
};

dlms::security::SecurityKey MakeAuthenticationKey()
{
  dlms::security::SecurityKey key =
    dlms::security::EmptySecurityKey(
      dlms::security::SecurityKeyRole::Authentication);
  key.size = 16u;
  for (std::size_t i = 0u; i < key.size; ++i) {
    key.bytes[i] = static_cast<std::uint8_t>(0x40u + i);
  }
  return key;
}

dlms::security::SecurityContext MakeContext(
  dlms::security::SecurityRole role)
{
  dlms::security::SecurityContext context =
    dlms::security::EmptySecurityContext();
  context.policy = dlms::security::SecurityPolicy::Authenticated;
  context.role = role;
  context.clientSap = 48u;
  context.serverSap = 1u;

  const std::uint8_t clientTitle[8] =
    {0x48u, 0x4cu, 0x53u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u};
  const std::uint8_t serverTitle[8] =
    {0x48u, 0x4cu, 0x53u, 0x00u, 0x00u, 0x00u, 0x00u, 0x02u};

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

void InstallAuthenticationKey(dlms::security::InMemoryKeyStore& keys)
{
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    keys.SetKey(MakeAuthenticationKey()));
}

} // namespace

TEST(HlsGmacAuthenticator, BuildsDeterministicChallenge)
{
  dlms::security::InMemoryKeyStore keys;
  dlms::security::InMemoryInvocationCounterStore counters;
  FixedRandomSource random(0x20u);

  dlms::security::HlsGmacAuthenticator hls(
    MakeContext(dlms::security::SecurityRole::Client),
    keys,
    counters,
    random);

  std::vector<std::uint8_t> challenge;
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    hls.BuildChallenge(challenge));
  ASSERT_EQ(dlms::security::HlsGmacAuthenticator::kChallengeSize,
            challenge.size());
  EXPECT_EQ(0x20u, challenge[0]);
  EXPECT_EQ(0x2fu, challenge[15]);
}

TEST(HlsGmacAuthenticator, BuildsAndVerifiesResponse)
{
  dlms::security::InMemoryKeyStore keys;
  InstallAuthenticationKey(keys);

  dlms::security::InMemoryInvocationCounterStore clientCounters;
  clientCounters.SetLocalCounter(3u);
  dlms::security::InMemoryInvocationCounterStore serverCounters;
  FixedRandomSource random(0x30u);

  dlms::security::HlsGmacAuthenticator client(
    MakeContext(dlms::security::SecurityRole::Client),
    keys,
    clientCounters,
    random);
  dlms::security::HlsGmacAuthenticator server(
    MakeContext(dlms::security::SecurityRole::Server),
    keys,
    serverCounters,
    random);

  std::vector<std::uint8_t> challenge;
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    server.BuildChallenge(challenge));

  std::vector<std::uint8_t> response;
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    client.BuildResponse(ViewOf(challenge), response));

  ASSERT_EQ(1u + 4u + 16u, response.size());
  EXPECT_EQ(0x10u, response[0]);
  EXPECT_EQ(0x00u, response[1]);
  EXPECT_EQ(0x00u, response[2]);
  EXPECT_EQ(0x00u, response[3]);
  EXPECT_EQ(0x03u, response[4]);

  EXPECT_EQ(
    dlms::security::SecurityStatus::Ok,
    server.VerifyResponse(ViewOf(challenge), ViewOf(response)));
}

TEST(HlsGmacAuthenticator, RejectsTamperedResponse)
{
  dlms::security::InMemoryKeyStore keys;
  InstallAuthenticationKey(keys);

  dlms::security::InMemoryInvocationCounterStore clientCounters;
  clientCounters.SetLocalCounter(5u);
  dlms::security::InMemoryInvocationCounterStore serverCounters;
  FixedRandomSource random(0x40u);

  dlms::security::HlsGmacAuthenticator client(
    MakeContext(dlms::security::SecurityRole::Client),
    keys,
    clientCounters,
    random);
  dlms::security::HlsGmacAuthenticator server(
    MakeContext(dlms::security::SecurityRole::Server),
    keys,
    serverCounters,
    random);

  std::vector<std::uint8_t> challenge;
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    server.BuildChallenge(challenge));

  std::vector<std::uint8_t> response;
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    client.BuildResponse(ViewOf(challenge), response));

  response[response.size() - 1u] ^= 0x01u;
  EXPECT_EQ(
    dlms::security::SecurityStatus::AuthenticationFailed,
    server.VerifyResponse(ViewOf(challenge), ViewOf(response)));
}

TEST(HlsGmacAuthenticator, RejectsReplayAfterSuccessfulVerify)
{
  dlms::security::InMemoryKeyStore keys;
  InstallAuthenticationKey(keys);

  dlms::security::InMemoryInvocationCounterStore clientCounters;
  clientCounters.SetLocalCounter(8u);
  dlms::security::InMemoryInvocationCounterStore serverCounters;
  FixedRandomSource random(0x50u);

  dlms::security::HlsGmacAuthenticator client(
    MakeContext(dlms::security::SecurityRole::Client),
    keys,
    clientCounters,
    random);
  dlms::security::HlsGmacAuthenticator server(
    MakeContext(dlms::security::SecurityRole::Server),
    keys,
    serverCounters,
    random);

  std::vector<std::uint8_t> challenge;
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    server.BuildChallenge(challenge));

  std::vector<std::uint8_t> response;
  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    client.BuildResponse(ViewOf(challenge), response));

  ASSERT_EQ(
    dlms::security::SecurityStatus::Ok,
    server.VerifyResponse(ViewOf(challenge), ViewOf(response)));
  EXPECT_EQ(
    dlms::security::SecurityStatus::ReplayDetected,
    server.VerifyResponse(ViewOf(challenge), ViewOf(response)));
}

TEST(HlsGmacAuthenticator, RejectsMissingAuthenticationKey)
{
  dlms::security::InMemoryKeyStore keys;
  dlms::security::InMemoryInvocationCounterStore counters;
  FixedRandomSource random(0x60u);

  dlms::security::HlsGmacAuthenticator hls(
    MakeContext(dlms::security::SecurityRole::Client),
    keys,
    counters,
    random);

  const std::uint8_t challenge[] = {0x01u};
  dlms::security::SecurityByteView view;
  view.data = challenge;
  view.size = sizeof(challenge);

  std::vector<std::uint8_t> response;
  EXPECT_EQ(
    dlms::security::SecurityStatus::MissingKey,
    hls.BuildResponse(view, response));
}
