/**
 * @file base64.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-encryption-cpp/base64.hpp"
#include <stdexcept>
#include <cstring>
#include <openssl/evp.h>
#include <vector>
#include <memory>

namespace
{
struct bio_free_all
{
    void operator()(BIO* p)
    {
        BIO_free_all(p);
    }
};
} // namespace

namespace octo::encryption
{
std::string Base64::base64_encode(const std::string& plain_text)
{
    // Assert input size
    if (plain_text.empty())
    {
        return "";
    }

    // Create a BIO base64 with free all deleter
    std::unique_ptr<BIO, bio_free_all> b64(BIO_new(BIO_f_base64()));

    // Create the sink and push the data to it
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO* sink = BIO_new(BIO_s_mem());
    BIO_push(b64.get(), sink);

    // Encode and flush
    BIO_write(b64.get(), plain_text.data(), plain_text.size());
    BIO_flush(b64.get());

    // Get encoded data
    const char* encoded;
    const long len = BIO_get_mem_data(sink, &encoded);
    return std::string(encoded, len);
}

std::string Base64::base64_decode(const std::string& encoded_text)
{
    // Assert input size
    if (encoded_text.empty())
    {
        return "";
    }

    // Create a BIO base64 with free all deleter
    std::unique_ptr<BIO, bio_free_all> b64(BIO_new(BIO_f_base64()));

    // Create the sink and push the data to it
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO* source = BIO_new_mem_buf(encoded_text.c_str(), -1); // read-only source
    BIO_push(b64.get(), source);

    // Decode
    const auto maxlen = encoded_text.size() / 4 * 3 + 1;
    std::vector<std::uint8_t> decoded(maxlen);
    const int len = BIO_read(b64.get(), decoded.data(), maxlen);
    decoded.resize(len);

    // Clear and return
    std::string decoded_str(decoded.begin(), decoded.end());
    std::memset(&decoded[0], 0, decoded.size());
    return decoded_str;
}
} // namespace octo::encryption