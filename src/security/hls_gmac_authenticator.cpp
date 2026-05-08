#include "dlms/security/hls_gmac_authenticator.hpp"

#include "dlms/security/suite0_aes_gcm.hpp"

namespace dlms {
namespace security {

const std::size_t HlsGmacAuthenticator::kChallengeSize;
const std::size_t HlsGmacAuthenticator::kResponseTagSize;

namespace {

const std::size_t kSecurityControlSize = 1u;
const std::size_t kInvocationCounterSize = 4u;
const std::size_t kResponseHeaderSize =
  kSecurityControlSize + kInvocationCounterSize;
const std::uint8_t kGmacSecurityControl = 0x10u;

SecurityStatus ValidateHlsContext(const SecurityContext& context)
{
  if (context.suite != SecuritySuite::Suite0) {
    return SecurityStatus::UnsupportedFeature;
  }

  if (context.clientSap == 0u || context.serverSap == 0u) {
    return SecurityStatus::InvalidContext;
  }

  if (!IsValidSystemTitle(context.localSystemTitle) ||
      !IsValidSystemTitle(context.remoteSystemTitle)) {
    return SecurityStatus::InvalidSystemTitle;
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

SecurityStatus GetAuthenticationKey(
  const IKeyStore& keys,
  SecurityKey& key)
{
  SecurityStatus status = keys.GetKey(SecurityKeyRole::Authentication, key);
  if (status != SecurityStatus::Ok) {
    return status;
  }
  return ValidateSecurityKey(SecuritySuite::Suite0, key);
}

void BuildGmacAad(
  SecurityByteView challenge,
  const SecurityKey& authenticationKey,
  std::vector<std::uint8_t>& aad)
{
  aad.clear();
  aad.reserve(1u + authenticationKey.size + challenge.size);
  aad.push_back(kGmacSecurityControl);
  aad.insert(
    aad.end(),
    authenticationKey.bytes,
    authenticationKey.bytes + authenticationKey.size);
  aad.insert(aad.end(), challenge.data, challenge.data + challenge.size);
}

SecurityStatus BuildTag(
  const std::uint8_t systemTitle[8],
  std::uint32_t invocationCounter,
  SecurityByteView challenge,
  const SecurityKey& authenticationKey,
  std::uint8_t tag[HlsGmacAuthenticator::kResponseTagSize])
{
  std::uint8_t nonce[Suite0AesGcm::kNonceSize] = {};
  SecurityStatus status = BuildNonce(systemTitle, invocationCounter, nonce);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  std::vector<std::uint8_t> aad;
  BuildGmacAad(challenge, authenticationKey, aad);

  AesGcmParameters parameters;
  parameters.nonce = ViewOf(nonce, sizeof(nonce));
  parameters.additionalAuthenticatedData = ViewOf(aad);
  parameters.input = ViewOf(0, 0u);

  std::vector<std::uint8_t> cipherText;
  Suite0AesGcm cipher;
  return cipher.Seal(authenticationKey, parameters, cipherText, tag);
}

} // namespace

HlsGmacAuthenticator::HlsGmacAuthenticator(
  const SecurityContext& context,
  const IKeyStore& keys,
  IInvocationCounterStore& counters,
  IRandomSource& random)
  : context_(context),
    keys_(keys),
    counters_(counters),
    random_(random)
{
}

SecurityStatus HlsGmacAuthenticator::BuildChallenge(
  std::vector<std::uint8_t>& challenge) const
{
  challenge.assign(kChallengeSize, 0u);
  SecurityStatus status = random_.Fill(&challenge[0], challenge.size());
  if (status != SecurityStatus::Ok) {
    challenge.clear();
    return status;
  }
  return SecurityStatus::Ok;
}

SecurityStatus HlsGmacAuthenticator::BuildResponse(
  SecurityByteView challenge,
  std::vector<std::uint8_t>& response) const
{
  response.clear();
  if (!IsValidSecurityByteView(challenge) || challenge.size == 0u) {
    return SecurityStatus::InvalidArgument;
  }

  SecurityStatus status = ValidateHlsContext(context_);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  SecurityKey authenticationKey =
    EmptySecurityKey(SecurityKeyRole::Authentication);
  status = GetAuthenticationKey(keys_, authenticationKey);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  std::uint32_t invocationCounter = 0u;
  status = counters_.NextLocal(invocationCounter);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  std::uint8_t tag[kResponseTagSize] = {};
  status = BuildTag(
    context_.localSystemTitle,
    invocationCounter,
    challenge,
    authenticationKey,
    tag);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  response.reserve(kResponseHeaderSize + sizeof(tag));
  response.push_back(kGmacSecurityControl);
  WriteBigEndian32(invocationCounter, response);
  response.insert(response.end(), tag, tag + sizeof(tag));
  return SecurityStatus::Ok;
}

SecurityStatus HlsGmacAuthenticator::VerifyResponse(
  SecurityByteView challenge,
  SecurityByteView response) const
{
  if (!IsValidSecurityByteView(challenge) || challenge.size == 0u ||
      !IsValidSecurityByteView(response)) {
    return SecurityStatus::InvalidArgument;
  }

  SecurityStatus status = ValidateHlsContext(context_);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  if (response.size != kResponseHeaderSize + kResponseTagSize) {
    return SecurityStatus::InvalidArgument;
  }

  if (response.data[0] != kGmacSecurityControl) {
    return SecurityStatus::AuthenticationFailed;
  }

  SecurityKey authenticationKey =
    EmptySecurityKey(SecurityKeyRole::Authentication);
  status = GetAuthenticationKey(keys_, authenticationKey);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  const std::uint32_t invocationCounter =
    ReadBigEndian32(response.data + kSecurityControlSize);

  std::uint8_t expectedTag[kResponseTagSize] = {};
  status = BuildTag(
    context_.remoteSystemTitle,
    invocationCounter,
    challenge,
    authenticationKey,
    expectedTag);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  for (std::size_t i = 0u; i < kResponseTagSize; ++i) {
    if (response.data[kResponseHeaderSize + i] != expectedTag[i]) {
      return SecurityStatus::AuthenticationFailed;
    }
  }

  status = counters_.ValidateRemote(invocationCounter);
  if (status != SecurityStatus::Ok) {
    return status;
  }

  return SecurityStatus::Ok;
}

} // namespace security
} // namespace dlms
