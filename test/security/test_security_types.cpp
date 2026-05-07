#include "dlms/security/security_types.hpp"

#include <gtest/gtest.h>

namespace {

void FillSystemTitle(std::uint8_t title[8])
{
  for (std::size_t i = 0u; i < 8u; ++i) {
    title[i] = static_cast<std::uint8_t>(0x10u + i);
  }
}

dlms::security::SecurityContext ValidProtectedContext()
{
  dlms::security::SecurityContext context =
    dlms::security::EmptySecurityContext();
  context.policy = dlms::security::SecurityPolicy::AuthenticatedAndEncrypted;
  context.clientSap = 16u;
  context.serverSap = 1u;
  FillSystemTitle(context.localSystemTitle);
  FillSystemTitle(context.remoteSystemTitle);
  return context;
}

} // namespace

TEST(SecurityTypes, EmptyByteViewIsValid)
{
  dlms::security::SecurityByteView view = {0, 0u};
  EXPECT_TRUE(dlms::security::IsValidSecurityByteView(view));
}

TEST(SecurityTypes, NonEmptyByteViewRequiresData)
{
  dlms::security::SecurityByteView view = {0, 1u};
  EXPECT_FALSE(dlms::security::IsValidSecurityByteView(view));
}

TEST(SecurityTypes, SuiteKeySizesMatchPlan)
{
  EXPECT_EQ(16u,
            dlms::security::RequiredKeySize(
              dlms::security::SecuritySuite::Suite0));
  EXPECT_EQ(16u,
            dlms::security::RequiredKeySize(
              dlms::security::SecuritySuite::Suite1));
  EXPECT_EQ(32u,
            dlms::security::RequiredKeySize(
              dlms::security::SecuritySuite::Suite2));
}

TEST(SecurityTypes, ValidatesSuite0KeyLength)
{
  dlms::security::SecurityKey key =
    dlms::security::EmptySecurityKey(
      dlms::security::SecurityKeyRole::GlobalUnicastEncryption);
  key.size = 16u;

  EXPECT_EQ(dlms::security::SecurityStatus::Ok,
            dlms::security::ValidateSecurityKey(
              dlms::security::SecuritySuite::Suite0,
              key));
}

TEST(SecurityTypes, RejectsMissingAndWrongLengthKeys)
{
  dlms::security::SecurityKey key =
    dlms::security::EmptySecurityKey(
      dlms::security::SecurityKeyRole::Authentication);

  EXPECT_EQ(dlms::security::SecurityStatus::MissingKey,
            dlms::security::ValidateSecurityKey(
              dlms::security::SecuritySuite::Suite0,
              key));

  key.size = 12u;
  EXPECT_EQ(dlms::security::SecurityStatus::InvalidKeyLength,
            dlms::security::ValidateSecurityKey(
              dlms::security::SecuritySuite::Suite0,
              key));
}

TEST(SecurityTypes, EmptyContextIsInvalid)
{
  EXPECT_EQ(dlms::security::SecurityStatus::InvalidContext,
            dlms::security::ValidateSecurityContext(
              dlms::security::EmptySecurityContext()));
}

TEST(SecurityTypes, NoSecurityContextDoesNotRequireSystemTitles)
{
  dlms::security::SecurityContext context =
    dlms::security::EmptySecurityContext();
  context.clientSap = 16u;
  context.serverSap = 1u;

  EXPECT_EQ(dlms::security::SecurityStatus::Ok,
            dlms::security::ValidateSecurityContext(context));
}

TEST(SecurityTypes, ProtectedContextRequiresSystemTitles)
{
  dlms::security::SecurityContext context =
    dlms::security::EmptySecurityContext();
  context.policy = dlms::security::SecurityPolicy::Authenticated;
  context.clientSap = 16u;
  context.serverSap = 1u;

  EXPECT_EQ(dlms::security::SecurityStatus::InvalidSystemTitle,
            dlms::security::ValidateSecurityContext(context));
}

TEST(SecurityTypes, ValidProtectedContextPasses)
{
  EXPECT_EQ(dlms::security::SecurityStatus::Ok,
            dlms::security::ValidateSecurityContext(
              ValidProtectedContext()));
}

TEST(SecurityTypes, NonSuite0ContextIsUnsupportedForNow)
{
  dlms::security::SecurityContext context = ValidProtectedContext();
  context.suite = dlms::security::SecuritySuite::Suite1;

  EXPECT_EQ(dlms::security::SecurityStatus::UnsupportedFeature,
            dlms::security::ValidateSecurityContext(context));
}
