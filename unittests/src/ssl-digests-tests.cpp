/**
 * @file ssl-digests-tests.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#include <catch2/catch_all.hpp>
#include "octo-encryption-cpp/digests/ssl/ssl-digest.hpp"

namespace
{
constexpr const char SIMPLE_PLAIN_TEXT[] = "This is a plain text to be hashed";
constexpr const char FILE_DATA_CHUNK1[] =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus vulputate luctus mattis. Suspendisse fermentum "
    "sagittis velit, eu rhoncus tortor cursus eu. In aliquam, turpis nec scelerisque rhoncus, dolor tortor iaculis "
    "est, pretium pretium quam velit id purus. Ut porttitor nisi ut eros pulvinar dictum. Aliquam sed nulla fermentum, "
    "bibendum libero vel, congue nisl. Proin tristique, turpis vel rutrum gravida, lorem velit feugiat nunc, at "
    "euismod odio ipsum sed diam. Phasellus vitae sapien nec tortor gravida semper.";
constexpr const char FILE_DATA_CHUNK2[] =
    "Ut euismod fringilla commodo. Morbi dignissim tincidunt odio, id suscipit magna sodales ornare. Nullam a quam "
    "vitae lacus tincidunt efficitur. In tristique justo a nisi feugiat interdum a ac erat. Phasellus vel risus magna. "
    "Donec ultrices eleifend velit ut bibendum. Integer tempor ligula ut erat efficitur iaculis. Duis sodales porta "
    "pretium. Sed lobortis faucibus velit et tempus.";
constexpr const char FILE_DATA_CHUNK3[] =
    "Duis non porttitor ipsum, non viverra dolor. Nullam id scelerisque purus. In hac habitasse platea dictumst. Nulla "
    "facilisi. Ut at ligula sed ipsum ultrices tempor ullamcorper vel justo. Nulla tempus, tortor vel sollicitudin "
    "auctor, odio augue facilisis ex, vitae scelerisque dui quam non eros. Pellentesque vitae nunc orci. Aliquam et "
    "consectetur nibh. Donec auctor ut dolor id finibus. In porta tellus vitae nulla eleifend hendrerit. Pellentesque "
    "vulputate tempus nisi, nec accumsan quam tristique sed. Vestibulum auctor eleifend pharetra. Donec vulputate, "
    "mauris in hendrerit suscipit, lectus quam sollicitudin nulla, pellentesque consectetur dolor lectus ut dui. "
    "Integer lobortis, ex nec accumsan bibendum, nisl purus elementum diam, in feugiat arcu tellus eu lacus. Donec "
    "neque odio, auctor eget metus ut, venenatis accumsan tellus.";
constexpr const char FILE_DATA_CHUNK4[] =
    "Vivamus sit amet ex ut mauris feugiat finibus nec at leo. Donec a enim sem. Nunc rutrum efficitur velit ut "
    "luctus. Fusce imperdiet eros sit amet velit iaculis imperdiet. Curabitur suscipit posuere dui, et ultricies "
    "neque. Mauris venenatis commodo augue id faucibus. Pellentesque vitae consectetur sem. Aenean quis justo erat. "
    "Phasellus ac lacinia diam.";
constexpr const char FILE_DATA_CHUNK5[] =
    "Aliquam convallis vehicula hendrerit. Morbi tincidunt sollicitudin fermentum. Cras aliquet ex ut ullamcorper "
    "efficitur. Etiam vulputate nisl a arcu volutpat iaculis. Morbi pulvinar tempus ipsum. Maecenas faucibus eros eget "
    "aliquet ullamcorper. Etiam eu laoreet magna. Proin eget odio dolor. Suspendisse luctus fermentum magna ac "
    "convallis. Suspendisse non sollicitudin nunc. Suspendisse iaculis tellus non orci tristique, sagittis ullamcorper "
    "ex commodo. Nunc ac elit eu lorem eleifend blandit vitae non ante.";
} // namespace

const std::pair<octo::encryption::DigestSharedPtr, std::string> digests_simple[] = {
    {std::make_shared<octo::encryption::ssl::Sha224Digest>(),
     "a00d8a2dc0678544528f769be713d5dc10ffbfe04e31efd1543ad0d0"},
    {std::make_shared<octo::encryption::ssl::Sha256Digest>(),
     "1b05ce399c8181803aa0e6717c23987d5104c9f32565685a68fa1babadf6947e"},
    {std::make_shared<octo::encryption::ssl::Sha384Digest>(),
     "de6574e153e579da191b989dcf38be25a8f20266e3ea2812eabef740d866a768ce1cec8accb8606ef504d07ba0a2439f"},
    {std::make_shared<octo::encryption::ssl::Sha512Digest>(),
     "46454dea35e4e58812ec7db8d424a50f871f66af6ab9cfc5c3fa2f4e9b1160c330ddbd72811db1765598051b6eafe2258e1a9fe6ce489f067"
     "e0a2840ba55a5a4"}};

const std::pair<octo::encryption::DigestSharedPtr, std::string> digests_empty[] = {
    {std::make_shared<octo::encryption::ssl::Sha224Digest>(),
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
    {std::make_shared<octo::encryption::ssl::Sha256Digest>(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {std::make_shared<octo::encryption::ssl::Sha384Digest>(),
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
    {std::make_shared<octo::encryption::ssl::Sha512Digest>(),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a"
        "538327af927da3e"}};

const std::pair<octo::encryption::DigestSharedPtr, std::string> digests_chunks[] = {
    {std::make_shared<octo::encryption::ssl::Sha224Digest>(),
        "040abc9ba69bc339119b9e58ab69f7b4b960a62a0f146aafdeb358ac"},
    {std::make_shared<octo::encryption::ssl::Sha256Digest>(),
        "46d5f77048d84305a937649ddc379052a3394cb229055d3f5443782c8f2c306d"},
    {std::make_shared<octo::encryption::ssl::Sha384Digest>(),
        "56bb301833145fe31a8b03ded17f6bdaa54e3d9d7433cbf7c4283b44b0a29fba2540bc5128303492ae1ef0f8dbcb38b6"},
    {std::make_shared<octo::encryption::ssl::Sha512Digest>(),
        "594bc4c8127b4b62333a663425bf2a5197ebcf70aef072b6b8f0a5a0ef2829065dda2b11b673e77d7e68ef7192ec2f9d40fe39df8d2e0079c"
        "f20c05f3355b098"}};

TEST_CASE("Different Digests", "[digest]")
{
    SECTION("Digests Validation")
    {
        auto s = GENERATE(digests_simple);
        s->first->update(SIMPLE_PLAIN_TEXT);
        REQUIRE(s->first->finalize() == s->second);
    }

    SECTION("Empty Validation")
    {
        auto s = GENERATE(digests_empty);
        REQUIRE(s->first->finalize() == s->second);
    }

    SECTION("Chunks Validation")
    {
        auto s = GENERATE(digests_chunks);
        s->first->update(FILE_DATA_CHUNK1);
        s->first->update(FILE_DATA_CHUNK2);
        s->first->update(FILE_DATA_CHUNK3);
        s->first->update(FILE_DATA_CHUNK4);
        s->first->update(FILE_DATA_CHUNK5);
        REQUIRE(s->first->finalize() == s->second);
    }
}