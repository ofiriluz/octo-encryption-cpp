/**
 * @file base64-tests.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#include <catch2/catch_all.hpp>
#include "octo-encryption-cpp/base64.hpp"

TEST_CASE("Encoding Tests", "[base64]")
{
    SECTION("Basic Encoding")
    {
        std::string text = "This is some text";
        REQUIRE(octo::encryption::Base64::base64_encode(text) == "VGhpcyBpcyBzb21lIHRleHQ=");
    }
    SECTION("Empty Encoding")
    {
        std::string text = "";
        REQUIRE(octo::encryption::Base64::base64_encode(text) == "");
    }
}

TEST_CASE("Decoding Tests", "[base64]")
{
    SECTION("Basic Decoding")
    {
        std::string text = "VGhpcyBpcyBzb21lIHRleHQ=";
        REQUIRE(octo::encryption::Base64::base64_decode(text) == "This is some text");
    }
    SECTION("Empty Decoding")
    {
        std::string text = "";
        REQUIRE(octo::encryption::Base64::base64_decode(text) == "");
    }
}

TEST_CASE("Encoding Decoding Tests", "[base64]")
{
    auto s = GENERATE("SomePassword",
                      "Some_Password",
                      "Some###Password",
                      "Djr57822XoLm$^&",
                      "Djr57822XoLmqwdqwdqw",
                      "1234567890AbCdEf#@",
                      "Some Spaces Password For Shtivi 123 @#$^",
                      "KEKBUR",
                      "12eqfihfefeiqfh",
                      "A",
                      "AB",
                      "ABC",
                      "ABCD",
                      "ABCDE",
                      "ABCDEF",
                      "ABCDEFG",
                      "ABCDEFGH",
                      "ABCDEFGHI",
                      "ABCDEFGHIJ",
                      "ABCDEFGHIJK",
                      "ABCDEFGHIJKL",
                      "ABCDEFGHIJKLM",
                      "ABCDEFGHIJKLMN",
                      "ABCDEFGHIJKLMNO",
                      "ABCDEFGHIJKLMNOP",
                      "ABCDEFGHIJKLMNOPQ",
                      "ABCDEFGHIJKLMNOPQR",
                      "ABCDEFGHIJKLMNOPQRS",
                      "ABCDEFGHIJKLMNOPQRST",
                      "ABCDEFGHIJKLMNOPQRSTU",
                      "ABCDEFGHIJKLMNOPQRSTUV",
                      "ABCDEFGHIJKLMNOPQRSTUVW",
                      "ABCDEFGHIJKLMNOPQRSTUVWX",
                      "ABCDEFGHIJKLMNOPQRSTUVWXY",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZa",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZab",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabc",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcd",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcde",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvw",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy",
                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                      "&尙\\x8c�\t�T5�dT!��");
    std::string encoded_text = octo::encryption::Base64::base64_encode(s);
    REQUIRE(octo::encryption::Base64::base64_decode(encoded_text) == s);
}