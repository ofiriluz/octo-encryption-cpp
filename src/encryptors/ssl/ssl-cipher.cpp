/**
 * @file ssl-cipher.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-encryption-cpp/encryptors/ssl/ssl-cipher.hpp"
#include <stdexcept>

namespace octo::encryption::ssl
{
SSLCipher::SSLCipher(const EVP_CIPHER* ssl_cipher) : ssl_cipher_(ssl_cipher)
{
}

SSLCipher::SSLCipher(const std::string& name)
{
    ssl_cipher_ = EVP_get_cipherbyname(name.c_str());
    if (!ssl_cipher_)
    {
        throw std::runtime_error("Failed to find SSL Cipher by name");
    }
}

SSLCipher::SSLCipher(int type)
{
    ssl_cipher_ = EVP_get_cipherbynid(type);
    if (!ssl_cipher_)
    {
        throw std::runtime_error("Failed to find SSL Cipher by type");
    }
}

const EVP_CIPHER* SSLCipher::cipher() const
{
    return ssl_cipher_;
}

int SSLCipher::type() const
{
    return EVP_CIPHER_nid(ssl_cipher_);
}

std::string SSLCipher::name() const
{
    return std::string(OBJ_nid2sn(type()));
}

std::size_t SSLCipher::block_size() const
{
    return EVP_CIPHER_block_size(ssl_cipher_);
}

std::size_t SSLCipher::key_length() const
{
    return EVP_CIPHER_key_length(ssl_cipher_);
}

std::size_t SSLCipher::iv_length() const
{
    return EVP_CIPHER_iv_length(ssl_cipher_);
}

unsigned long SSLCipher::flags() const
{
    return EVP_CIPHER_flags(ssl_cipher_);
}

unsigned long SSLCipher::mode() const
{
    return EVP_CIPHER_mode(ssl_cipher_);
}
} // namespace octo::encryption::ssl