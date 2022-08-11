/**
 * @file encrypted-string-tests.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#include <catch2/catch_all.hpp>
#include "octo-encryption-cpp/encryptors/encrypted-string.hpp"
#include "octo-encryption-cpp/encryptors/ssl/ssl-encryptor.hpp"
#include "octo-encryption-cpp/encryptors/materials/simple-material.hpp"

TEST_CASE("Encryption Decryption", "[encrypted-string]")
{
    std::string input_plain_string("Hello World!");
    auto encryptor = std::make_shared<octo::encryption::ssl::SSLEncryptor>(
        std::make_shared<octo::encryption::ssl::SSLCipher>("AES256"));
    auto material = std::make_shared<octo::encryption::SimpleMaterial>(std::vector<std::string>{"Key1", "Key2", "Key3"});
    SECTION("Set Get")
    {
        octo::encryption::SingleEncryptedString encrypted_string(encryptor);

        // Encryption
        encrypted_string.set(input_plain_string, material);

        // Decryption
        auto output_plain_string = encrypted_string.get();

        REQUIRE(input_plain_string == output_plain_string);
    }

    SECTION("Ctor")
    {
        octo::encryption::SingleEncryptedString encrypted_string(encryptor);

        // Encryption
        encrypted_string.set(input_plain_string, material);

        octo::encryption::SingleEncryptedString encrypted_string2(encrypted_string.cipher(), material, encryptor);

        // Decryption
        auto output_plain_string = encrypted_string2.get();

        REQUIRE(input_plain_string == output_plain_string);
    }

    SECTION("Destruct")
    {
        octo::encryption::SingleEncryptedString encrypted_string(encryptor);

        // Encryption
        encrypted_string.set(input_plain_string, material);

        octo::encryption::SingleEncryptedString encrypted_string2(encrypted_string.cipher(), material, encryptor);

        // Decryption
        const std::string& output_plain_string = encrypted_string2.get();

        REQUIRE(input_plain_string == output_plain_string);

        encrypted_string2.destruct();

        REQUIRE(std::string("") == output_plain_string);
    }
}