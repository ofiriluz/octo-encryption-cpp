/**
 * @file ssl-digest.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef SSL_DIGEST_HPP_
#define SSL_DIGEST_HPP_

#include "octo-encryption-cpp/digests/digest.hpp"
#include <memory>
#include <functional>
#include <openssl/evp.h>

namespace octo::encryption::ssl
{
class SSLDigest : public Digest
{
  protected:
    EVP_MD_CTX* digest_context_;

  protected:
    /**
     * @brief Init the SSL digest based on the implemented class
     *
     */
    virtual void init_ssl_digest() = 0;

  public:
    SSLDigest();
    ~SSLDigest() override;

    void update(const std::string& plain_text) override;
    void update(const std::vector<char>& plain_text, std::size_t size) override;
    void update(const char* plain_text, std::size_t size) override;
    void update(const std::uint8_t* plain_text, std::size_t size) override;
    void reset() override;
    std::string finalize() override;
    std::size_t length() override;
};

class Sha224Digest final : public SSLDigest
{
  protected:
    void init_ssl_digest() override;

  public:
    Sha224Digest() = default;
    ~Sha224Digest() override = default;

    std::unique_ptr<Digest> clone() override;
};

class Sha256Digest final : public SSLDigest
{
  protected:
    void init_ssl_digest() override;

  public:
    Sha256Digest() = default;
    ~Sha256Digest() override = default;

    std::unique_ptr<Digest> clone() override;
};

class Sha384Digest final : public SSLDigest
{
  protected:
    void init_ssl_digest() override;

  public:
    Sha384Digest() = default;
    ~Sha384Digest() override = default;

    std::unique_ptr<Digest> clone() override;
};

class Sha512Digest final : public SSLDigest
{
  protected:
    void init_ssl_digest() override;

  public:
    Sha512Digest() = default;
    ~Sha512Digest() override = default;

    std::unique_ptr<Digest> clone() override;
};
} // namespace octo::encryption::ssl

#endif // SSL_DIGEST_HPP_