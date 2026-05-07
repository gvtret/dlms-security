#include "dlms/security/in_memory_invocation_counter_store.hpp"

#include <gtest/gtest.h>

#include <limits>

TEST(InMemoryInvocationCounterStore, LocalCounterIsMonotonic)
{
  dlms::security::InMemoryInvocationCounterStore store;
  std::uint32_t first = 0u;
  std::uint32_t second = 0u;

  EXPECT_EQ(dlms::security::SecurityStatus::Ok, store.NextLocal(first));
  EXPECT_EQ(dlms::security::SecurityStatus::Ok, store.NextLocal(second));
  EXPECT_EQ(1u, first);
  EXPECT_EQ(2u, second);
}

TEST(InMemoryInvocationCounterStore, ReportsLocalCounterExhaustion)
{
  dlms::security::InMemoryInvocationCounterStore store;
  store.SetLocalCounter(std::numeric_limits<std::uint32_t>::max());

  std::uint32_t counter = 0u;
  EXPECT_EQ(dlms::security::SecurityStatus::InvocationCounterExhausted,
            store.NextLocal(counter));
}

TEST(InMemoryInvocationCounterStore, RemoteCounterMustBeNonZero)
{
  dlms::security::InMemoryInvocationCounterStore store;

  EXPECT_EQ(dlms::security::SecurityStatus::InvalidInvocationCounter,
            store.ValidateRemote(0u));
}

TEST(InMemoryInvocationCounterStore, RejectsReplayOrStaleRemoteCounter)
{
  dlms::security::InMemoryInvocationCounterStore store;

  ASSERT_EQ(dlms::security::SecurityStatus::Ok, store.ValidateRemote(10u));
  EXPECT_EQ(dlms::security::SecurityStatus::ReplayDetected,
            store.ValidateRemote(10u));
  EXPECT_EQ(dlms::security::SecurityStatus::ReplayDetected,
            store.ValidateRemote(9u));
  EXPECT_EQ(dlms::security::SecurityStatus::Ok,
            store.ValidateRemote(11u));
}
