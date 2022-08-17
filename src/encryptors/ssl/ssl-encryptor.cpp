/**
 * @file ssl-encryptor.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-encryption-cpp/encryptors/ssl/ssl-encryptor.hpp"
#include "octo-encryption-cpp/digests/ssl/ssl-digest.hpp"
#include "octo-encryption-cpp/base64.hpp"
#include <openssl/evp.h>
#include <vector>
#include <sstream>
#include <cstring>
#include <iterator>

namespace octo::encryption::ssl
{
SSLEncryptor::SSLEncryptor(const SSLCipherSharedPtr& cipher) : ssl_cipher_(cipher)
{
}

std::unique_ptr<std::uint8_t[]> SSLEncryptor::generate_key_material(const MaterialPtr& material)
{
    // Create the material array
    auto materials = material->generate();

    // Concat the materials
    std::ostringstream imploded;
    std::copy(materials.begin(), materials.end(), std::ostream_iterator<std::string>(imploded, ""));

    // Perform MGF1 to get the key based on the cipher key length
    // We base it off SHA1 for now
    // Prepare the out buffer
    auto mask_size = ssl_cipher_->key_length();
    auto masked = std::make_unique<std::uint8_t[]>(mask_size + 1);

    // Output length
    std::size_t out_len = 0;

    // Digest used
    auto digest = std::make_unique<Sha256Digest>();
    auto md_len = digest->length() * 2;

    // Make sure we dont exceed length
    if (mask_size + md_len < md_len)
    {
        throw std::runtime_error("Key generation size exceeded");
    }

    // Insert the starting key
    digest->update(imploded.str());
    std::uint8_t mgf_counter[4] = {0};

    // Roll out until size reaches mask
    for (int i = 0; out_len < mask_size; i++)
    {
        mgf_counter[0] = (std::uint8_t)((i >> 24) & 255);
        mgf_counter[1] = (std::uint8_t)((i >> 16) & 255);
        mgf_counter[2] = (std::uint8_t)((i >> 8) & 255);
        mgf_counter[3] = (std::uint8_t)(i & 255);
        auto cloned = digest->clone();
        cloned->update((std::uint8_t*)mgf_counter, 4);
        auto out_str = cloned->finalize();
        if (out_len + md_len <= mask_size)
        {
            std::memcpy(masked.get() + out_len, out_str.c_str(), md_len);
            out_len += out_str.size();
        }
        else
        {
            std::memcpy(masked.get() + out_len, out_str.c_str(), mask_size - out_len);
            out_len = mask_size;
        }
        Encryptor::secure_zeromem(out_str);
    }

    return masked;
}

std::string SSLEncryptor::encrypt(const std::string& message, const MaterialPtr& material)
{
    if (!material)
    {
        throw std::runtime_error("Invalid encryption parameters given");
    }

    int out_len = message.size() + ssl_cipher_->block_size();
    int temp_len = 0;

    std::vector<std::uint8_t> out_str(out_len, 0);
    std::vector<std::uint8_t> iv(ssl_cipher_->iv_length(), 0); // Temporary IV set to 0 for now
    std::unique_ptr<EVP_CIPHER_CTX, std::function<void(EVP_CIPHER_CTX*)>> ctx(
        EVP_CIPHER_CTX_new(), [](EVP_CIPHER_CTX* ctx) { EVP_CIPHER_CTX_free(ctx); });
    EVP_CIPHER_CTX_init(ctx.get());
    auto key = std::move(generate_key_material(material));
    if (!EVP_CipherInit_ex(ctx.get(), ssl_cipher_->cipher(), nullptr, key.get(), iv.data(), 1))
    {
        throw std::runtime_error("Failed to cipher init");
    }

    if (!EVP_CipherUpdate(
            ctx.get(), &out_str[0], &temp_len, reinterpret_cast<const std::uint8_t*>(&message[0]), message.size()))
    {
        throw std::runtime_error("Failed to cipher update");
    }
    out_len = temp_len;

    if (!EVP_CipherFinal_ex(ctx.get(), &out_str[out_len], &temp_len))
    {
        throw std::runtime_error("Failed to cipher finalize");
    }
    out_len += temp_len;

    auto encoded = Base64::base64_encode(std::string(reinterpret_cast<char const*>(&out_str[0]), out_len));
    Encryptor::secure_zeromem(out_str);
    return encoded;
}

std::size_t SSLEncryptor::decrypt(const std::string& message, const MaterialPtr& material, std::string& out_buffer)
{
    if (!material)
    {
        throw std::runtime_error("Invalid decryption parameters given");
    }

    auto decoded_message = Base64::base64_decode(message);
    int out_len = decoded_message.size() + ssl_cipher_->block_size();
    int temp_len = 0;
    std::vector<std::uint8_t> out_str(out_len, 0);
    std::vector<std::uint8_t> iv(ssl_cipher_->iv_length(), 0); // Temporary IV set to 0 for now
    std::unique_ptr<EVP_CIPHER_CTX, std::function<void(EVP_CIPHER_CTX*)>> ctx(
        EVP_CIPHER_CTX_new(), [](EVP_CIPHER_CTX* ctx) { EVP_CIPHER_CTX_free(ctx); });
    EVP_CIPHER_CTX_init(ctx.get());
    auto key = generate_key_material(material);
    if (!EVP_CipherInit_ex(ctx.get(), ssl_cipher_->cipher(), nullptr, key.get(), iv.data(), 0))
    {
        throw std::runtime_error("Failed to cipher init");
    }

    if (!EVP_CipherUpdate(ctx.get(),
                          &out_str[0],
                          &temp_len,
                          reinterpret_cast<const std::uint8_t*>(decoded_message.c_str()),
                          decoded_message.size()))
    {
        throw std::runtime_error("Failed to cipher update");
    }
    out_len = temp_len;

    if (!EVP_CipherFinal_ex(ctx.get(), &out_str[out_len], &temp_len))
    {
        throw std::runtime_error("Failed to cipher finalize");
    }
    out_len += temp_len;

    Encryptor::secure_zeromem(decoded_message);
    out_buffer = std::string(out_str.begin(), out_str.begin() + out_len);
    Encryptor::secure_zeromem(out_str);

    return out_len;
}
} // namespace octo::encryption::ssl