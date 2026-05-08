#include "dlms/security/suite0_aes_gcm.hpp"

#include <algorithm>
#include <limits>

#include <openssl/evp.h>

namespace dlms {
namespace security {
namespace {

bool IsValidTagPointer(const std::uint8_t* tag)
{
  return tag != 0;
}

SecurityStatus ValidateAesGcmInput(
  const SecurityKey& key,
  const AesGcmParameters& parameters,
  const std::uint8_t* tag)
{
  const SecurityStatus keyStatus =
    ValidateSecurityKey(SecuritySuite::Suite0, key);
  if (keyStatus != SecurityStatus::Ok) {
    return keyStatus;
  }

  if (!IsValidSecurityByteView(parameters.nonce) ||
      parameters.nonce.size != Suite0AesGcm::kNonceSize) {
    return SecurityStatus::InvalidArgument;
  }

  if (!IsValidSecurityByteView(parameters.additionalAuthenticatedData) ||
      !IsValidSecurityByteView(parameters.input) ||
      !IsValidTagPointer(tag)) {
    return SecurityStatus::InvalidArgument;
  }

  return SecurityStatus::Ok;
}

class EvpCipherContext
{
public:
  EvpCipherContext()
    : context_(EVP_CIPHER_CTX_new())
  {
  }

  ~EvpCipherContext()
  {
    if (context_ != 0) {
      EVP_CIPHER_CTX_free(context_);
    }
  }

  bool IsValid() const
  {
    return context_ != 0;
  }

  EVP_CIPHER_CTX* Get() const
  {
    return context_;
  }

private:
  EvpCipherContext(const EvpCipherContext&);
  EvpCipherContext& operator=(const EvpCipherContext&);

  EVP_CIPHER_CTX* context_;
};

bool SizeFitsInt(std::size_t size)
{
  return size <= static_cast<std::size_t>(std::numeric_limits<int>::max());
}

SecurityStatus OpenSslSeal(
  const SecurityKey& key,
  const AesGcmParameters& parameters,
  std::vector<std::uint8_t>& cipherText,
  std::uint8_t tag[Suite0AesGcm::kTagSize])
{
  if (!SizeFitsInt(parameters.input.size) ||
      !SizeFitsInt(parameters.additionalAuthenticatedData.size)) {
    return SecurityStatus::InvalidArgument;
  }

  EvpCipherContext context;
  if (!context.IsValid()) {
    return SecurityStatus::CipherFailed;
  }

  if (EVP_EncryptInit_ex(context.Get(), EVP_aes_128_gcm(), 0, 0, 0) != 1 ||
      EVP_CIPHER_CTX_ctrl(
        context.Get(),
        EVP_CTRL_GCM_SET_IVLEN,
        static_cast<int>(parameters.nonce.size),
        0) != 1 ||
      EVP_EncryptInit_ex(
        context.Get(),
        0,
        0,
        key.bytes,
        parameters.nonce.data) != 1) {
    return SecurityStatus::CipherFailed;
  }

  int outputSize = 0;
  if (parameters.additionalAuthenticatedData.size != 0u &&
      EVP_EncryptUpdate(
        context.Get(),
        0,
        &outputSize,
        parameters.additionalAuthenticatedData.data,
        static_cast<int>(
          parameters.additionalAuthenticatedData.size)) != 1) {
    return SecurityStatus::CipherFailed;
  }

  cipherText.assign(parameters.input.size, 0u);
  if (parameters.input.size != 0u &&
      EVP_EncryptUpdate(
        context.Get(),
        &cipherText[0],
        &outputSize,
        parameters.input.data,
        static_cast<int>(parameters.input.size)) != 1) {
    cipherText.clear();
    return SecurityStatus::CipherFailed;
  }

  int finalSize = 0;
  if (EVP_EncryptFinal_ex(
        context.Get(),
        cipherText.empty() ? 0 : &cipherText[0] + outputSize,
        &finalSize) != 1 ||
      EVP_CIPHER_CTX_ctrl(
        context.Get(),
        EVP_CTRL_GCM_GET_TAG,
        static_cast<int>(Suite0AesGcm::kTagSize),
        tag) != 1) {
    cipherText.clear();
    return SecurityStatus::CipherFailed;
  }

  cipherText.resize(static_cast<std::size_t>(outputSize + finalSize));
  return SecurityStatus::Ok;
}

SecurityStatus OpenSslOpen(
  const SecurityKey& key,
  const AesGcmParameters& parameters,
  const std::uint8_t tag[Suite0AesGcm::kTagSize],
  std::vector<std::uint8_t>& plainText)
{
  if (!SizeFitsInt(parameters.input.size) ||
      !SizeFitsInt(parameters.additionalAuthenticatedData.size)) {
    return SecurityStatus::InvalidArgument;
  }

  EvpCipherContext context;
  if (!context.IsValid()) {
    return SecurityStatus::DecipherFailed;
  }

  if (EVP_DecryptInit_ex(context.Get(), EVP_aes_128_gcm(), 0, 0, 0) != 1 ||
      EVP_CIPHER_CTX_ctrl(
        context.Get(),
        EVP_CTRL_GCM_SET_IVLEN,
        static_cast<int>(parameters.nonce.size),
        0) != 1 ||
      EVP_DecryptInit_ex(
        context.Get(),
        0,
        0,
        key.bytes,
        parameters.nonce.data) != 1) {
    return SecurityStatus::DecipherFailed;
  }

  int outputSize = 0;
  if (parameters.additionalAuthenticatedData.size != 0u &&
      EVP_DecryptUpdate(
        context.Get(),
        0,
        &outputSize,
        parameters.additionalAuthenticatedData.data,
        static_cast<int>(
          parameters.additionalAuthenticatedData.size)) != 1) {
    return SecurityStatus::DecipherFailed;
  }

  plainText.assign(parameters.input.size, 0u);
  if (parameters.input.size != 0u &&
      EVP_DecryptUpdate(
        context.Get(),
        &plainText[0],
        &outputSize,
        parameters.input.data,
        static_cast<int>(parameters.input.size)) != 1) {
    plainText.clear();
    return SecurityStatus::DecipherFailed;
  }

  if (EVP_CIPHER_CTX_ctrl(
        context.Get(),
        EVP_CTRL_GCM_SET_TAG,
        static_cast<int>(Suite0AesGcm::kTagSize),
        const_cast<std::uint8_t*>(tag)) != 1) {
    plainText.clear();
    return SecurityStatus::DecipherFailed;
  }

  int finalSize = 0;
  if (EVP_DecryptFinal_ex(
        context.Get(),
        plainText.empty() ? 0 : &plainText[0] + outputSize,
        &finalSize) != 1) {
    plainText.clear();
    return SecurityStatus::DecipherFailed;
  }

  plainText.resize(static_cast<std::size_t>(outputSize + finalSize));
  return SecurityStatus::Ok;
}

} // namespace

SecurityStatus Suite0AesGcm::Seal(
  const SecurityKey& key,
  const AesGcmParameters& parameters,
  std::vector<std::uint8_t>& cipherText,
  std::uint8_t tag[kTagSize]) const
{
  cipherText.clear();
  const SecurityStatus validation = ValidateAesGcmInput(key, parameters, tag);
  if (validation != SecurityStatus::Ok) {
    return validation;
  }
  std::fill(tag, tag + kTagSize, 0u);

  return OpenSslSeal(key, parameters, cipherText, tag);
}

SecurityStatus Suite0AesGcm::Open(
  const SecurityKey& key,
  const AesGcmParameters& parameters,
  const std::uint8_t tag[kTagSize],
  std::vector<std::uint8_t>& plainText) const
{
  plainText.clear();
  const SecurityStatus validation = ValidateAesGcmInput(key, parameters, tag);
  if (validation != SecurityStatus::Ok) {
    return validation;
  }

  return OpenSslOpen(key, parameters, tag, plainText);
}

} // namespace security
} // namespace dlms
