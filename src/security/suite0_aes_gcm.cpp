#include "dlms/security/suite0_aes_gcm.hpp"

#include <algorithm>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#endif

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

#if defined(_WIN32)

class BCryptAlgorithm
{
public:
  BCryptAlgorithm()
    : handle_(0)
  {
  }

  ~BCryptAlgorithm()
  {
    if (handle_ != 0) {
      BCryptCloseAlgorithmProvider(handle_, 0u);
    }
  }

  SecurityStatus Open()
  {
    NTSTATUS status = BCryptOpenAlgorithmProvider(
      &handle_,
      BCRYPT_AES_ALGORITHM,
      0,
      0u);
    if (status < 0) {
      return SecurityStatus::CipherFailed;
    }

    status = BCryptSetProperty(
      handle_,
      BCRYPT_CHAINING_MODE,
      reinterpret_cast<PUCHAR>(
        const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
      static_cast<ULONG>(
        (wcslen(BCRYPT_CHAIN_MODE_GCM) + 1u) * sizeof(wchar_t)),
      0u);
    if (status < 0) {
      return SecurityStatus::CipherFailed;
    }

    return SecurityStatus::Ok;
  }

  BCRYPT_ALG_HANDLE Get() const
  {
    return handle_;
  }

private:
  BCryptAlgorithm(const BCryptAlgorithm&);
  BCryptAlgorithm& operator=(const BCryptAlgorithm&);

  BCRYPT_ALG_HANDLE handle_;
};

class BCryptKey
{
public:
  BCryptKey()
    : handle_(0)
  {
  }

  ~BCryptKey()
  {
    if (handle_ != 0) {
      BCryptDestroyKey(handle_);
    }
  }

  SecurityStatus Generate(
    BCRYPT_ALG_HANDLE algorithm,
    const SecurityKey& key)
  {
    NTSTATUS status = BCryptGenerateSymmetricKey(
      algorithm,
      &handle_,
      0,
      0u,
      const_cast<PUCHAR>(key.bytes),
      static_cast<ULONG>(key.size),
      0u);
    if (status < 0) {
      return SecurityStatus::InvalidKeyLength;
    }
    return SecurityStatus::Ok;
  }

  BCRYPT_KEY_HANDLE Get() const
  {
    return handle_;
  }

private:
  BCryptKey(const BCryptKey&);
  BCryptKey& operator=(const BCryptKey&);

  BCRYPT_KEY_HANDLE handle_;
};

PUCHAR DataPointer(SecurityByteView view)
{
  return const_cast<PUCHAR>(view.data);
}

SecurityStatus BCryptSealOrOpen(
  bool seal,
  const SecurityKey& key,
  const AesGcmParameters& parameters,
  std::vector<std::uint8_t>& output,
  std::uint8_t tag[Suite0AesGcm::kTagSize])
{
  BCryptAlgorithm algorithm;
  SecurityStatus status = algorithm.Open();
  if (status != SecurityStatus::Ok) {
    return status;
  }

  BCryptKey bcryptKey;
  status = bcryptKey.Generate(algorithm.Get(), key);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
  BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
  authInfo.pbNonce = DataPointer(parameters.nonce);
  authInfo.cbNonce = static_cast<ULONG>(parameters.nonce.size);
  authInfo.pbAuthData =
    DataPointer(parameters.additionalAuthenticatedData);
  authInfo.cbAuthData =
    static_cast<ULONG>(parameters.additionalAuthenticatedData.size);
  authInfo.pbTag = tag;
  authInfo.cbTag = static_cast<ULONG>(Suite0AesGcm::kTagSize);

  output.assign(parameters.input.size, 0u);
  ULONG outputSize = 0u;
  PUCHAR input = DataPointer(parameters.input);
  PUCHAR outputData = output.empty() ? 0 : &output[0];

  NTSTATUS ntstatus = seal
    ? BCryptEncrypt(
        bcryptKey.Get(),
        input,
        static_cast<ULONG>(parameters.input.size),
        &authInfo,
        0,
        0u,
        outputData,
        static_cast<ULONG>(output.size()),
        &outputSize,
        0u)
    : BCryptDecrypt(
        bcryptKey.Get(),
        input,
        static_cast<ULONG>(parameters.input.size),
        &authInfo,
        0,
        0u,
        outputData,
        static_cast<ULONG>(output.size()),
        &outputSize,
        0u);

  if (ntstatus < 0) {
    output.clear();
    return seal ? SecurityStatus::CipherFailed : SecurityStatus::DecipherFailed;
  }

  output.resize(outputSize);
  return SecurityStatus::Ok;
}

#endif

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

#if defined(_WIN32)
  return BCryptSealOrOpen(true, key, parameters, cipherText, tag);
#else
  return SecurityStatus::UnsupportedFeature;
#endif
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

  std::uint8_t mutableTag[kTagSize] = {};
  for (std::size_t i = 0u; i < kTagSize; ++i) {
    mutableTag[i] = tag[i];
  }

#if defined(_WIN32)
  return BCryptSealOrOpen(false, key, parameters, plainText, mutableTag);
#else
  return SecurityStatus::UnsupportedFeature;
#endif
}

} // namespace security
} // namespace dlms
