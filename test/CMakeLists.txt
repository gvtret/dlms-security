if(DLMS_USE_SYSTEM_GTEST)
  find_package(GTest REQUIRED)
elseif(NOT TARGET GTest::gtest_main)
  include(FetchContent)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_MakeAvailable(googletest)
endif()

add_executable(dlms_security_tests
  security/test_invocation_counter_store.cpp
  security/test_key_store.cpp
  security/test_suite0_aes_gcm.cpp
  security/test_security_status.cpp
  security/test_security_types.cpp)

target_link_libraries(dlms_security_tests
  PRIVATE
    dlms_security
    GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(dlms_security_tests)
