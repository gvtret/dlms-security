#include "dlms/security/hls_high_authenticator.hpp"

#include <gtest/gtest.h>

#include <string>

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

dlms::security::SecurityByteView ViewOf(
  const std::vector<std::uint8_t>& bytes)
{
  dlms::security::SecurityByteView view;
  view.data = bytes.empty() ? 0 : &bytes[0];
  view.size = bytes.size();
  return view;
}

dlms::security::SecurityByteView ViewOf(const char* text)
{
  dlms::security::SecurityByteView view;
  view.data = reinterpret_cast<const std::uint8_t*>(text);
  view.size = text == 0 ? 0u : std::char_traits<char>::length(text);
  return view;
}

} // namespace

TEST(HlsHighAuthenticator, BuildsDeterministicChallenge)
{
  FixedRandomSource random(0x20u);
  dlms::security::HlsHighAuthenticator hls(ViewOf("HiPassword"), random);

  std::vector<std::uint8_t> challenge;
  ASSERT_EQ(dlms::security::SecurityStatus::Ok,
            hls.BuildChallenge(challenge));

  ASSERT_EQ(dlms::security::HlsHighAuthenticator::kChallengeSize,
            challenge.size());
  EXPECT_EQ(0x20u, challenge[0]);
  EXPECT_EQ(0x2fu, challenge[15]);
}

TEST(HlsHighAuthenticator, BuildsGuruxCompatibleResponse)
{
  FixedRandomSource random(0x00u);
  dlms::security::HlsHighAuthenticator hls(ViewOf("HiPassword"), random);
  const std::uint8_t challengeBytes[16] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu};
  dlms::security::SecurityByteView challenge;
  challenge.data = challengeBytes;
  challenge.size = sizeof(challengeBytes);

  std::vector<std::uint8_t> response;
  ASSERT_EQ(dlms::security::SecurityStatus::Ok,
            hls.BuildResponse(challenge, response));

  const std::uint8_t expected[] = {
    0x93u, 0xabu, 0x97u, 0x43u, 0xa2u, 0x91u, 0xa9u, 0x04u,
    0x02u, 0xe6u, 0x9du, 0x8fu, 0x3au, 0xd5u, 0xa1u, 0x7cu};
  EXPECT_EQ(std::vector<std::uint8_t>(expected, expected + sizeof(expected)),
            response);
}

TEST(HlsHighAuthenticator, VerifiesMatchingResponse)
{
  FixedRandomSource random(0x00u);
  dlms::security::HlsHighAuthenticator hls(ViewOf("HiPassword"), random);
  std::vector<std::uint8_t> challenge;
  ASSERT_EQ(dlms::security::SecurityStatus::Ok,
            hls.BuildChallenge(challenge));
  std::vector<std::uint8_t> response;
  ASSERT_EQ(dlms::security::SecurityStatus::Ok,
            hls.BuildResponse(ViewOf(challenge), response));

  EXPECT_EQ(dlms::security::SecurityStatus::Ok,
            hls.VerifyResponse(ViewOf(challenge), ViewOf(response)));

  response[0] ^= 0x01u;
  EXPECT_EQ(dlms::security::SecurityStatus::AuthenticationFailed,
            hls.VerifyResponse(ViewOf(challenge), ViewOf(response)));
}

TEST(HlsHighAuthenticator, RejectsMissingPassword)
{
  FixedRandomSource random(0x00u);
  dlms::security::SecurityByteView empty = {};
  dlms::security::HlsHighAuthenticator hls(empty, random);
  std::vector<std::uint8_t> response;

  EXPECT_EQ(dlms::security::SecurityStatus::InvalidArgument,
            hls.BuildResponse(empty, response));
}
