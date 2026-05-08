#include "dlms/security/suite0_aes_gcm.hpp"

#include <gtest/gtest.h>

namespace {

dlms::security::SecurityKey MakeZeroKey()
{
  dlms::security::SecurityKey key =
    dlms::security::EmptySecurityKey(
      dlms::security::SecurityKeyRole::GlobalUnicastEncryption);
  key.size = dlms::security::Suite0AesGcm::kKeySize;
  return key;
}

std::vector<std::uint8_t> Bytes(const std::uint8_t* data, std::size_t size)
{
  return std::vector<std::uint8_t>(data, data + size);
}

dlms::security::SecurityByteView View(
  const std::vector<std::uint8_t>& data)
{
  dlms::security::SecurityByteView view;
  view.data = data.empty() ? 0 : &data[0];
  view.size = data.size();
  return view;
}

dlms::security::AesGcmParameters Params(
  const std::vector<std::uint8_t>& nonce,
  const std::vector<std::uint8_t>& aad,
  const std::vector<std::uint8_t>& input)
{
  dlms::security::AesGcmParameters parameters;
  parameters.nonce = View(nonce);
  parameters.additionalAuthenticatedData = View(aad);
  parameters.input = View(input);
  return parameters;
}

} // namespace

TEST(Suite0AesGcm, SealsNistEmptyPlaintextVector)
{
  const std::uint8_t expectedTagBytes[] = {
    0x58, 0xE2, 0xFC, 0xCE, 0xFA, 0x7E, 0x30, 0x61,
    0x36, 0x7F, 0x1D, 0x57, 0xA4, 0xE7, 0x45, 0x5A};
  const std::vector<std::uint8_t> nonce(12u, 0u);
  const std::vector<std::uint8_t> aad;
  const std::vector<std::uint8_t> plainText;

  std::vector<std::uint8_t> cipherText;
  std::uint8_t tag[dlms::security::Suite0AesGcm::kTagSize] = {};
  dlms::security::Suite0AesGcm engine;

  EXPECT_EQ(dlms::security::SecurityStatus::Ok,
            engine.Seal(
              MakeZeroKey(),
              Params(nonce, aad, plainText),
              cipherText,
              tag));
  EXPECT_TRUE(cipherText.empty());
  EXPECT_EQ(Bytes(expectedTagBytes, sizeof(expectedTagBytes)),
            Bytes(tag, sizeof(tag)));
}

TEST(Suite0AesGcm, SealsAndOpensNistSingleBlockVector)
{
  const std::uint8_t expectedCipherTextBytes[] = {
    0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92,
    0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78};
  const std::uint8_t expectedTagBytes[] = {
    0xAB, 0x6E, 0x47, 0xD4, 0x2C, 0xEC, 0x13, 0xBD,
    0xF5, 0x3A, 0x67, 0xB2, 0x12, 0x57, 0xBD, 0xDF};
  const std::vector<std::uint8_t> nonce(12u, 0u);
  const std::vector<std::uint8_t> aad;
  const std::vector<std::uint8_t> plainText(16u, 0u);

  std::vector<std::uint8_t> cipherText;
  std::uint8_t tag[dlms::security::Suite0AesGcm::kTagSize] = {};
  dlms::security::Suite0AesGcm engine;

  ASSERT_EQ(dlms::security::SecurityStatus::Ok,
            engine.Seal(
              MakeZeroKey(),
              Params(nonce, aad, plainText),
              cipherText,
              tag));
  EXPECT_EQ(Bytes(expectedCipherTextBytes, sizeof(expectedCipherTextBytes)),
            cipherText);
  EXPECT_EQ(Bytes(expectedTagBytes, sizeof(expectedTagBytes)),
            Bytes(tag, sizeof(tag)));

  std::vector<std::uint8_t> opened;
  EXPECT_EQ(dlms::security::SecurityStatus::Ok,
            engine.Open(
              MakeZeroKey(),
              Params(nonce, aad, cipherText),
              tag,
              opened));
  EXPECT_EQ(plainText, opened);
}

TEST(Suite0AesGcm, RejectsInvalidTag)
{
  const std::vector<std::uint8_t> nonce(12u, 0u);
  const std::vector<std::uint8_t> aad;
  const std::vector<std::uint8_t> plainText(16u, 0u);
  dlms::security::Suite0AesGcm engine;
  std::vector<std::uint8_t> cipherText;
  std::uint8_t tag[dlms::security::Suite0AesGcm::kTagSize] = {};

  ASSERT_EQ(dlms::security::SecurityStatus::Ok,
            engine.Seal(
              MakeZeroKey(),
              Params(nonce, aad, plainText),
              cipherText,
              tag));
  tag[0] ^= 0x01u;

  std::vector<std::uint8_t> opened;
  EXPECT_EQ(dlms::security::SecurityStatus::DecipherFailed,
            engine.Open(
              MakeZeroKey(),
              Params(nonce, aad, cipherText),
              tag,
              opened));
  EXPECT_TRUE(opened.empty());
}

TEST(Suite0AesGcm, RejectsInvalidInputs)
{
  const std::vector<std::uint8_t> shortNonce(11u, 0u);
  const std::vector<std::uint8_t> aad;
  const std::vector<std::uint8_t> plainText;
  std::vector<std::uint8_t> cipherText;
  std::uint8_t tag[dlms::security::Suite0AesGcm::kTagSize] = {};
  dlms::security::Suite0AesGcm engine;

  EXPECT_EQ(dlms::security::SecurityStatus::InvalidArgument,
            engine.Seal(
              MakeZeroKey(),
              Params(shortNonce, aad, plainText),
              cipherText,
              tag));

  dlms::security::SecurityKey shortKey = MakeZeroKey();
  shortKey.size = 15u;
  EXPECT_EQ(dlms::security::SecurityStatus::InvalidKeyLength,
            engine.Seal(
              shortKey,
              Params(std::vector<std::uint8_t>(12u, 0u), aad, plainText),
              cipherText,
              tag));
}
