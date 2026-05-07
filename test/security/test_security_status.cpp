#include "dlms/security/security_status.hpp"

#include <gtest/gtest.h>

TEST(SecurityStatus, NamesStableValues)
{
  EXPECT_STREQ(
    "Ok",
    dlms::security::SecurityStatusName(
      dlms::security::SecurityStatus::Ok));
  EXPECT_STREQ(
    "InvalidContext",
    dlms::security::SecurityStatusName(
      dlms::security::SecurityStatus::InvalidContext));
  EXPECT_STREQ(
    "InvalidKeyLength",
    dlms::security::SecurityStatusName(
      dlms::security::SecurityStatus::InvalidKeyLength));
  EXPECT_STREQ(
    "ReplayDetected",
    dlms::security::SecurityStatusName(
      dlms::security::SecurityStatus::ReplayDetected));
  EXPECT_STREQ(
    "Unknown",
    dlms::security::SecurityStatusName(
      static_cast<dlms::security::SecurityStatus>(255)));
}
