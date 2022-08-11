/**
 * @file ssl-digest.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-encryption-cpp/digests/ssl/ssl-digest.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace octo::encryption::ssl
{
SSLDigest::SSLDigest() : digest_context_(nullptr)
{
}

SSLDigest::~SSLDigest()
{
    if (digest_context_)
    {
        EVP_MD_CTX_destroy(digest_context_);
        digest_context_ = nullptr;
    }
}

void SSLDigest::update(const std::string& plain_text)
{
    update(plain_text.c_str(), plain_text.size());
}

void SSLDigest::update(const std::vector<char>& plain_text, size_t size)
{
    update(plain_text.data(), size);
}

void SSLDigest::update(const char* plain_text, size_t size)
{
    // Reset the context if not already created, for lazy load
    if (!digest_context_)
    {
        reset();
    }

    // Perform the digest update and make sure it was successful
    int rc = EVP_DigestUpdate(digest_context_, plain_text, size);
    if (rc != 1)
    {
        throw std::runtime_error(std::string("Failed to update the SHA Digest [") + std::to_string(rc) +
                                 "] (Diagnostics Info: 3)");
    }
}

void SSLDigest::update(const uint8_t* plain_text, size_t size)
{
    // Reset the context if not already created, for lazy load
    if (!digest_context_)
    {
        reset();
    }

    // Perform the digest update and make sure it was successful
    int rc = EVP_DigestUpdate(digest_context_, plain_text, size);
    if (rc != 1)
    {
        throw std::runtime_error(std::string("Failed to update the SHA Digest [") + std::to_string(rc) +
                                 "] (Diagnostics Info: 4)");
    }
}

void SSLDigest::reset()
{
    // Create the digest of SSL
    if (digest_context_)
    {
        EVP_MD_CTX_destroy(digest_context_);
        digest_context_ = nullptr;
    }
    digest_context_ = EVP_MD_CTX_create();
    // Init the fitting SSL implementation
    init_ssl_digest();
}

std::string SSLDigest::finalize()
{
    // Reset the context if not already created, for lazy load
    if (!digest_context_)
    {
        reset();
    }

    uint8_t buffer[EVP_MAX_MD_SIZE];
    uint32_t digest_size = 0;
    std::memset(buffer, 0x00, EVP_MAX_MD_SIZE);

    // Perform the final digest and get the hash, make sure it was successful
    int rc = EVP_DigestFinal_ex(digest_context_, buffer, &digest_size);
    if (rc != 1)
    {
        throw std::runtime_error(std::string("Failed to finalize the SHA Digest [") + std::to_string(rc) + "]");
    }

    // Destroy the digest after we finalized it
    EVP_MD_CTX_destroy(digest_context_);
    digest_context_ = nullptr;

    // Transform the bytes string to a normal string
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < digest_size; i++)
    {
        ss << std::setw(2) << (int)buffer[i];
    }

    return ss.str();
}

size_t SSLDigest::length()
{
    // Reset the context if not already created, for lazy load
    if (!digest_context_)
    {
        reset();
    }
    return EVP_MD_CTX_size(digest_context_);
}

void Sha224Digest::init_ssl_digest()
{
    // Init the SHA224 digest and check if was successful
    int rc = EVP_DigestInit_ex(digest_context_, EVP_sha224(), nullptr);
    if (rc != 1)
    {
        throw std::runtime_error(std::string("Failed to initialize the SHA224 Digest [") + std::to_string(rc) + "]");
    }
}

std::unique_ptr<Digest> Sha224Digest::clone()
{
    auto digest = std::make_unique<Sha224Digest>();
    digest->digest_context_ = EVP_MD_CTX_create();
    if (digest_context_)
    {
        EVP_MD_CTX_copy_ex(digest->digest_context_, digest_context_);
    }
    return std::move(digest);
}

void Sha256Digest::init_ssl_digest()
{
    // Init the SHA256 digest and check if was successful
    int rc = EVP_DigestInit_ex(digest_context_, EVP_sha256(), nullptr);
    if (rc != 1)
    {
        throw std::runtime_error(std::string("Failed to initialize the SHA256 Digest [") + std::to_string(rc) + "]");
    }
}

std::unique_ptr<Digest> Sha256Digest::clone()
{
    auto digest = std::make_unique<Sha256Digest>();
    digest->digest_context_ = EVP_MD_CTX_create();
    if (digest_context_)
    {
        EVP_MD_CTX_copy_ex(digest->digest_context_, digest_context_);
    }
    return std::move(digest);
}

void Sha384Digest::init_ssl_digest()
{
    // Init the SHA384 digest and check if was successful
    int rc = EVP_DigestInit_ex(digest_context_, EVP_sha384(), nullptr);
    if (rc != 1)
    {
        throw std::runtime_error(std::string("Failed to initialize the SHA384 Digest [") + std::to_string(rc) + "]");
    }
}

std::unique_ptr<Digest> Sha384Digest::clone()
{
    auto digest = std::make_unique<Sha384Digest>();
    digest->digest_context_ = EVP_MD_CTX_create();
    if (digest_context_)
    {
        EVP_MD_CTX_copy_ex(digest->digest_context_, digest_context_);
    }
    return std::move(digest);
}

void Sha512Digest::init_ssl_digest()
{
    // Init the SHA512 digest and check if was successful
    int rc = EVP_DigestInit_ex(digest_context_, EVP_sha512(), nullptr);
    if (rc != 1)
    {
        throw std::runtime_error(std::string("Failed to initialize the SHA512 Digest [") + std::to_string(rc) + "]");
    }
}

std::unique_ptr<Digest> Sha512Digest::clone()
{
    auto digest = std::make_unique<Sha512Digest>();
    digest->digest_context_ = EVP_MD_CTX_create();
    if (digest_context_)
    {
        EVP_MD_CTX_copy_ex(digest->digest_context_, digest_context_);
    }
    return std::move(digest);
}
} // namespace octo::encryption::ssl