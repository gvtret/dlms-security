#include "dlms/security/hls_high_authenticator.hpp"

#include <algorithm>

#include <openssl/evp.h>

namespace dlms {
namespace security {

const std::size_t HlsHighAuthenticator::kChallengeSize;

namespace {

const std::size_t kAesBlockSize = 16u;

bool IsValidInput(SecurityByteView view)
{
  return view.data != 0 && view.size != 0u;
}

std::size_t RoundUpBlockSize(std::size_t size)
{
  const std::size_t remainder = size % kAesBlockSize;
  return remainder == 0u ? size : size + kAesBlockSize - remainder;
}

SecurityStatus Aes128EcbEncrypt(
  const std::uint8_t key[kAesBlockSize],
  std::vector<std::uint8_t>& data)
{
  EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
  if (context == 0) {
    return SecurityStatus::CipherFailed;
  }

  SecurityStatus status = SecurityStatus::Ok;
  int outputSize = 0;
  int finalSize = 0;

  if (EVP_EncryptInit_ex(context, EVP_aes_128_ecb(), 0, key, 0) != 1 ||
      EVP_CIPHER_CTX_set_padding(context, 0) != 1 ||
      EVP_EncryptUpdate(
        context,
        data.empty() ? 0 : &data[0],
        &outputSize,
        data.empty() ? 0 : &data[0],
        static_cast<int>(data.size())) != 1 ||
      EVP_EncryptFinal_ex(
        context,
        data.empty() ? 0 : &data[0] + outputSize,
        &finalSize) != 1) {
    status = SecurityStatus::CipherFailed;
  } else {
    data.resize(static_cast<std::size_t>(outputSize + finalSize));
  }

  EVP_CIPHER_CTX_free(context);
  return status;
}

SecurityStatus TransformHigh(
  SecurityByteView challenge,
  SecurityByteView password,
  std::vector<std::uint8_t>& response)
{
  if (!IsValidInput(challenge) || !IsValidInput(password)) {
    return SecurityStatus::InvalidArgument;
  }

  const std::size_t paddedSize =
    RoundUpBlockSize(std::max(challenge.size, password.size));
  response.assign(paddedSize, 0u);
  std::copy(challenge.data, challenge.data + challenge.size, response.begin());

  std::uint8_t key[kAesBlockSize] = {};
  const std::size_t keySize =
    std::min(password.size, static_cast<std::size_t>(kAesBlockSize));
  std::copy(password.data, password.data + keySize, key);

  return Aes128EcbEncrypt(key, response);
}

SecurityByteView ViewOf(const std::vector<std::uint8_t>& bytes)
{
  SecurityByteView view;
  view.data = bytes.empty() ? 0 : &bytes[0];
  view.size = bytes.size();
  return view;
}

} // namespace

HlsHighAuthenticator::HlsHighAuthenticator(
  SecurityByteView password,
  IRandomSource& random)
  : password_()
  , random_(random)
{
  if (IsValidInput(password)) {
    password_.assign(password.data, password.data + password.size);
  }
}

SecurityStatus HlsHighAuthenticator::BuildChallenge(
  std::vector<std::uint8_t>& challenge) const
{
  challenge.assign(kChallengeSize, 0u);
  const SecurityStatus status =
    random_.Fill(challenge.empty() ? 0 : &challenge[0], challenge.size());
  if (status != SecurityStatus::Ok) {
    challenge.clear();
  }
  return status;
}

SecurityStatus HlsHighAuthenticator::BuildResponse(
  SecurityByteView challenge,
  std::vector<std::uint8_t>& response) const
{
  return TransformHigh(challenge, ViewOf(password_), response);
}

SecurityStatus HlsHighAuthenticator::VerifyResponse(
  SecurityByteView challenge,
  SecurityByteView response) const
{
  std::vector<std::uint8_t> expected;
  const SecurityStatus status = BuildResponse(challenge, expected);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  if (response.size != expected.size() ||
      (response.size != 0u &&
       !std::equal(response.data, response.data + response.size,
                  expected.begin()))) {
    return SecurityStatus::AuthenticationFailed;
  }

  return SecurityStatus::Ok;
}

} // namespace security
} // namespace dlms
