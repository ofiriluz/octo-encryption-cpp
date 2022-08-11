CMAKE_MINIMUM_REQUIRED(VERSION 3.16)

PROJECT(octo-encryption-cpp)

# Add CMake options to path
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/)
INCLUDE(ConfigOptions)
INCLUDE(LoadConanBuildInfo)
LOAD_CONAN_BUILD_INFO()

# Library definition
ADD_LIBRARY(octo-encryption-cpp STATIC
    src/base64.cpp
    src/secure-random.cpp
    src/digests/ssl/ssl-digest.cpp
    src/encryptors/encryptor.cpp
    src/encryptors/sym-encrypt-layer-strategy.cpp
    src/encryptors/ssl/ssl-cipher.cpp
    src/encryptors/ssl/ssl-encryptor.cpp
)

# Alias
ADD_LIBRARY(core::octo-encryption-cpp ALIAS octo-encryption-cpp)

# Properties
SET_TARGET_PROPERTIES(octo-encryption-cpp PROPERTIES CXX_STANDARD 17 POSITION_INDEPENDENT_CODE ON)

TARGET_INCLUDE_DIRECTORIES(octo-encryption-cpp
    PUBLIC
        # Logger includes
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

TARGET_LINK_LIBRARIES(octo-encryption-cpp
    # System libraries
    CONAN_PKG::openssl
)

# Installation of the logger
INSTALL(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION include
)

INSTALL(TARGETS octo-encryption-cpp
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Unittests
IF(NOT DISABLE_TESTS)
    ENABLE_TESTING()
    ADD_SUBDIRECTORY(unittests)
ENDIF()
