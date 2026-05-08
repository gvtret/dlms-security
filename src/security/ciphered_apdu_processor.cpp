#include "dlms/security/ciphered_apdu_processor.hpp"

#include "dlms/security/suite0_aes_gcm.hpp"

#include <algorithm>

namespace dlms {
namespace security {
namespace {

const std::size_t kSecurityControlSize = 1u;
const std::size_t kInvocationCounterSize = 4u;
const std::size_t kHeaderSize = kSecurityControlSize + kInvocationCounterSize;

std::uint8_t SecurityControlForPolicy(SecurityPolicy policy)
{
  switch (policy) {
  case SecurityPolicy::None:
    return 0x00u;
  case SecurityPolicy::Authenticated:
    return 0x10u;
  case SecurityPolicy::Encrypted:
    return 0x20u;
  case SecurityPolicy::AuthenticatedAndEncrypted:
    return 0x30u;
  }

  return 0x00u;
}

bool IsSupportedPolicy(SecurityPolicy policy)
{
  return policy == SecurityPolicy::None ||
         policy == SecurityPolicy::AuthenticatedAndEncrypted;
}

SecurityStatus ValidateProcessorContext(const SecurityContext& context)
{
  const SecurityStatus status = ValidateSecurityContext(context);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  if (!IsSupportedPolicy(context.policy)) {
    return SecurityStatus::UnsupportedFeature;
  }

  return SecurityStatus::Ok;
}

void WriteBigEndian32(
  std::uint32_t value,
  std::vector<std::uint8_t>& output)
{
  output.push_back(static_cast<std::uint8_t>((value >> 24) & 0xffu));
  output.push_back(static_cast<std::uint8_t>((value >> 16) & 0xffu));
  output.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffu));
  output.push_back(static_cast<std::uint8_t>(value & 0xffu));
}

std::uint32_t ReadBigEndian32(const std::uint8_t* input)
{
  return (static_cast<std::uint32_t>(input[0]) << 24) |
         (static_cast<std::uint32_t>(input[1]) << 16) |
         (static_cast<std::uint32_t>(input[2]) << 8) |
         static_cast<std::uint32_t>(input[3]);
}

SecurityStatus BuildNonce(
  const std::uint8_t systemTitle[8],
  std::uint32_t invocationCounter,
  std::uint8_t nonce[Suite0AesGcm::kNonceSize])
{
  if (!IsValidSystemTitle(systemTitle)) {
    return SecurityStatus::InvalidSystemTitle;
  }

  for (std::size_t i = 0u; i < 8u; ++i) {
    nonce[i] = systemTitle[i];
  }
  nonce[8] = static_cast<std::uint8_t>((invocationCounter >> 24) & 0xffu);
  nonce[9] = static_cast<std::uint8_t>((invocationCounter >> 16) & 0xffu);
  nonce[10] = static_cast<std::uint8_t>((invocationCounter >> 8) & 0xffu);
  nonce[11] = static_cast<std::uint8_t>(invocationCounter & 0xffu);
  return SecurityStatus::Ok;
}

SecurityStatus GetSuite0Key(
  const IKeyStore& keys,
  SecurityKeyRole role,
  SecurityKey& key)
{
  SecurityStatus status = keys.GetKey(role, key);
  if (status != SecurityStatus::Ok) {
    return status;
  }
  return ValidateSecurityKey(SecuritySuite::Suite0, key);
}

void BuildAad(
  std::uint8_t securityControl,
  const SecurityKey& authenticationKey,
  std::vector<std::uint8_t>& aad)
{
  aad.clear();
  aad.reserve(1u + authenticationKey.size);
  aad.push_back(securityControl);
  aad.insert(
    aad.end(),
    authenticationKey.bytes,
    authenticationKey.bytes + authenticationKey.size);
}

SecurityByteView ViewOf(const std::vector<std::uint8_t>& data)
{
  SecurityByteView view;
  view.data = data.empty() ? 0 : &data[0];
  view.size = data.size();
  return view;
}

SecurityByteView ViewOf(
  const std::uint8_t* data,
  std::size_t size)
{
  SecurityByteView view;
  view.data = data;
  view.size = size;
  return view;
}

} // namespace

CipheredApduProcessor::CipheredApduProcessor(
  const SecurityContext& context,
  const IKeyStore& keys,
  IInvocationCounterStore& counters)
  : context_(context),
    keys_(keys),
    counters_(counters)
{
}

SecurityStatus CipheredApduProcessor::Protect(
  SecurityByteView plainApdu,
  std::vector<std::uint8_t>& protectedApdu) const
{
  protectedApdu.clear();
  if (!IsValidSecurityByteView(plainApdu)) {
    return SecurityStatus::InvalidArgument;
  }

  const SecurityStatus contextStatus = ValidateProcessorContext(context_);
  if (contextStatus != SecurityStatus::Ok) {
    return contextStatus;
  }

  if (context_.policy == SecurityPolicy::None) {
    if (plainApdu.size != 0u) {
      protectedApdu.assign(plainApdu.data, plainApdu.data + plainApdu.size);
    }
    return SecurityStatus::Ok;
  }

  SecurityKey encryptionKey =
    EmptySecurityKey(SecurityKeyRole::GlobalUnicastEncryption);
  SecurityStatus status = GetSuite0Key(
    keys_,
    SecurityKeyRole::GlobalUnicastEncryption,
    encryptionKey);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  SecurityKey authenticationKey =
    EmptySecurityKey(SecurityKeyRole::Authentication);
  status = GetSuite0Key(keys_, SecurityKeyRole::Authentication, authenticationKey);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  std::uint32_t invocationCounter = 0u;
  status = counters_.NextLocal(invocationCounter);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  std::uint8_t nonce[Suite0AesGcm::kNonceSize] = {};
  status = BuildNonce(context_.localSystemTitle, invocationCounter, nonce);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  const std::uint8_t securityControl =
    SecurityControlForPolicy(context_.policy);
  std::vector<std::uint8_t> aad;
  BuildAad(securityControl, authenticationKey, aad);

  std::vector<std::uint8_t> cipherText;
  std::uint8_t tag[Suite0AesGcm::kTagSize] = {};
  AesGcmParameters parameters;
  parameters.nonce = ViewOf(nonce, sizeof(nonce));
  parameters.additionalAuthenticatedData = ViewOf(aad);
  parameters.input = plainApdu;

  Suite0AesGcm cipher;
  status = cipher.Seal(encryptionKey, parameters, cipherText, tag);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  protectedApdu.reserve(kHeaderSize + cipherText.size() + sizeof(tag));
  protectedApdu.push_back(securityControl);
  WriteBigEndian32(invocationCounter, protectedApdu);
  protectedApdu.insert(protectedApdu.end(), cipherText.begin(), cipherText.end());
  protectedApdu.insert(protectedApdu.end(), tag, tag + sizeof(tag));
  return SecurityStatus::Ok;
}

SecurityStatus CipheredApduProcessor::Unprotect(
  SecurityByteView protectedApdu,
  std::vector<std::uint8_t>& plainApdu) const
{
  plainApdu.clear();
  if (!IsValidSecurityByteView(protectedApdu)) {
    return SecurityStatus::InvalidArgument;
  }

  const SecurityStatus contextStatus = ValidateProcessorContext(context_);
  if (contextStatus != SecurityStatus::Ok) {
    return contextStatus;
  }

  if (context_.policy == SecurityPolicy::None) {
    if (protectedApdu.size != 0u) {
      plainApdu.assign(
        protectedApdu.data,
        protectedApdu.data + protectedApdu.size);
    }
    return SecurityStatus::Ok;
  }

  const std::size_t minimumSize = kHeaderSize + Suite0AesGcm::kTagSize;
  if (protectedApdu.size < minimumSize) {
    return SecurityStatus::InvalidArgument;
  }

  const std::uint8_t expectedControl =
    SecurityControlForPolicy(context_.policy);
  if (protectedApdu.data[0] != expectedControl) {
    return SecurityStatus::AuthenticationFailed;
  }

  SecurityKey encryptionKey =
    EmptySecurityKey(SecurityKeyRole::GlobalUnicastEncryption);
  SecurityStatus status = GetSuite0Key(
    keys_,
    SecurityKeyRole::GlobalUnicastEncryption,
    encryptionKey);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  SecurityKey authenticationKey =
    EmptySecurityKey(SecurityKeyRole::Authentication);
  status = GetSuite0Key(keys_, SecurityKeyRole::Authentication, authenticationKey);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  const std::uint32_t invocationCounter =
    ReadBigEndian32(protectedApdu.data + kSecurityControlSize);
  std::uint8_t nonce[Suite0AesGcm::kNonceSize] = {};
  status = BuildNonce(context_.remoteSystemTitle, invocationCounter, nonce);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  std::vector<std::uint8_t> aad;
  BuildAad(expectedControl, authenticationKey, aad);

  const std::size_t cipherTextOffset = kHeaderSize;
  const std::size_t cipherTextSize =
    protectedApdu.size - minimumSize;
  const std::uint8_t* tag =
    protectedApdu.data + cipherTextOffset + cipherTextSize;

  AesGcmParameters parameters;
  parameters.nonce = ViewOf(nonce, sizeof(nonce));
  parameters.additionalAuthenticatedData = ViewOf(aad);
  parameters.input = ViewOf(
    protectedApdu.data + cipherTextOffset,
    cipherTextSize);

  Suite0AesGcm cipher;
  status = cipher.Open(encryptionKey, parameters, tag, plainApdu);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  status = counters_.ValidateRemote(invocationCounter);
  if (status != SecurityStatus::Ok) {
    plainApdu.clear();
    return status;
  }

  return SecurityStatus::Ok;
}

} // namespace security
} // namespace dlms
