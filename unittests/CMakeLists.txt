FIND_PACKAGE(Catch2 REQUIRED CONFIG)

# UT definition
ADD_EXECUTABLE(octo-encryption-cpp-tests
    src/base64-tests.cpp
    src/ssl-digests-tests.cpp
    src/ssl-encryptors-tests.cpp
    src/encrypted-string-tests.cpp
    src/test.cpp
)

# Properties
SET_TARGET_PROPERTIES(octo-encryption-cpp-tests PROPERTIES CXX_STANDARD 17 POSITION_INDEPENDENT_CODE ON)

TARGET_LINK_LIBRARIES(octo-encryption-cpp-tests
    octo-encryption-cpp

    Catch2::Catch2

    # System Libraries
    $<$<PLATFORM_ID:Linux>:pthread>
)

# Discover tests
INCLUDE(CTest)
INCLUDE(Catch)
CATCH_DISCOVER_TESTS(octo-encryption-cpp-tests)
