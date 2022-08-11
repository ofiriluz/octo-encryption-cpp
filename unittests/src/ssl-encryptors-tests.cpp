
#include <catch2/catch_all.hpp>
#include "octo-encryption-cpp/encryptors/ssl/ssl-encryptor.hpp"
#include "octo-encryption-cpp/encryptors/materials/simple-material.hpp"

namespace
{
constexpr const auto SMALLSTRING = "abc";
constexpr const auto LONGSTRING = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";
}

void test_encrypt_decrypt(const std::string & value,
                          octo::encryption::ssl::SSLEncryptor & encryptor,
                          const octo::encryption::MaterialPtr & material)
{
    std::string encrypted = encryptor.encrypt(value, material);
    std::string output;
    REQUIRE(encryptor.decrypt(encrypted, material, output) == value.size());
    REQUIRE(value == output);
}

TEST_CASE("Different Encryptions", "[encryptors]")
{
    auto materials = {
        std::make_shared<octo::encryption::SimpleMaterial>(std::vector<std::string>{"Key1"}),
        std::make_shared<octo::encryption::SimpleMaterial>(std::vector<std::string>{"Key2"}),
        std::make_shared<octo::encryption::SimpleMaterial>(std::vector<std::string>{"VeryLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongMaterial"}),
        std::make_shared<octo::encryption::SimpleMaterial>(std::vector<std::string>{"K"}),
        std::make_shared<octo::encryption::SimpleMaterial>(std::vector<std::string>{"E(HFWQ(FH(WE@FH@$(FH@FH(HF@("})
    };
    auto encryptor = octo::encryption::ssl::SSLEncryptor(std::make_shared<octo::encryption::ssl::SSLCipher>("AES256"));

    SECTION("Different Materials Empty String")
    {
        for(auto & m : materials)
        {
            test_encrypt_decrypt("", encryptor, m);
        }
    }
    SECTION("Different Materials Small String")
    {
        for(auto & m : materials)
        {
            test_encrypt_decrypt(SMALLSTRING, encryptor, m);
        }
    }
    SECTION("Different Materials Long String")
    {
        for(auto & m : materials)
        {
            test_encrypt_decrypt(LONGSTRING, encryptor, m);
        }
    }
    SECTION("Multiple Materials")
    {
        auto material = std::make_shared<octo::encryption::SimpleMaterial>(std::vector<std::string>{"Key1", "Key2", "Key3"});
        test_encrypt_decrypt(LONGSTRING, encryptor, material);
    }
    SECTION("Long Multiple Material")
    {
        auto material = std::make_shared<octo::encryption::SimpleMaterial>(std::vector<std::string>{"VeryLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongMaterial",
                                                                                                   "VeryLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongMaterial12312312312",
                                                                                                   "VeryLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLongMaterial9q302ye80q2390q89yrq23978r9qwauegsgfaeofg97e8aofgq3984g2493fg2943f"});
        test_encrypt_decrypt(LONGSTRING, encryptor, material);
    }
    SECTION("Different Algorithms")
    {
        auto material = std::make_shared<octo::encryption::SimpleMaterial>(std::vector<std::string>{"Key1", "Key2", "Key3"});
        auto algs = {"AES128", "AES192", "AES256"};
        for(auto & alg : algs)
        {
            auto e = octo::encryption::ssl::SSLEncryptor(std::make_shared<octo::encryption::ssl::SSLCipher>(alg));
            test_encrypt_decrypt(LONGSTRING, e, material);
        }
    }
}

TEST_CASE("Encryption", "[encryptor]")
{
    auto encryptor = octo::encryption::ssl::SSLEncryptor(std::make_shared<octo::encryption::ssl::SSLCipher>("AES256"));
    auto material = std::make_shared<octo::encryption::SimpleMaterial>(std::vector<std::string>{"Key1", "Key2", "Key3"});
    SECTION("Encryption Same Values")
    {
        std::string encrypted1 = encryptor.encrypt(LONGSTRING, material);
        std::string encrypted2 = encryptor.encrypt(LONGSTRING, material);
        REQUIRE(encrypted1 == encrypted2);
    }
}

TEST_CASE("Decryption", "[encryptor]")
{
    auto encryptor = octo::encryption::ssl::SSLEncryptor(std::make_shared<octo::encryption::ssl::SSLCipher>("AES256"));
    SECTION("Decryption Right Material")
    {
        std::string plain = "A9BE11F3762F6BD386D97C7F7F56408EE7073BD2FDE7FDD4418C85DBF1FFE7B9B0E33E4CA8E68D425D7A6FCFC69F50C28D04B90967B7A701496DD314405DCB56";
        std::string encrypted ="/R1VN7Qh9wndVE9ylGJqEobuNB5Wmx3WhnE2ncGJ/0K+0manObk22TiZjVrfMAnwh6itWfS+MyAzYAuCr1yD0mZXtKNwPfzROUMhgDIdMP1U7RWt4SZTKboCrl4t5ePS7bzQiNcTKgq4Y5Shnps2Im1rRdm8WzXy9db9P/Bu61vRfCsHhAPNijvrRYsrKJw5";
        auto material = std::make_shared<octo::encryption::SimpleMaterial>(std::vector<std::string>{"HostName123abc"});
        std::string output;

        REQUIRE(encryptor.decrypt(encrypted, material, output) == plain.size());
        REQUIRE(plain == output);
    }

    SECTION("Decryption Wrong Material")
    {
        std::string encrypted ="/R1VN7Qh9wndVE9ylGJqEobuNB5Wmx3WhnE2ncGJ/0K+0manObk22TiZjVrfMAnwh6itWfS+MyAzYAuCr1yD0mZXtKNwPfzROUMhgDIdMP1U7RWt4SZTKboCrl4t5ePS7bzQiNcTKgq4Y5Shnps2Im1rRdm8WzXy9db9P/Bu61vRfCsHhAPNijvrRYsrKJw5";
        auto material = std::make_shared<octo::encryption::SimpleMaterial>(std::vector<std::string>{"HostName123abcWRONG"});
        std::string output;

        REQUIRE_THROWS(encryptor.decrypt(encrypted, material, output));
    }
}