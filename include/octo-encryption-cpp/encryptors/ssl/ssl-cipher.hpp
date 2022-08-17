/**
 * @file ssl-cipher.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef SSL_CIPHER_HPP_
#define SSL_CIPHER_HPP_

#include <string>
#include <memory>
#include <openssl/evp.h>

namespace octo::encryption::ssl
{
class SSLCipher
{
  private:
    const EVP_CIPHER* ssl_cipher_;

  public:
    explicit SSLCipher(const EVP_CIPHER* ssl_cipher);
    explicit SSLCipher(const std::string& name);
    explicit SSLCipher(int type);
    ~SSLCipher() = default;

    [[nodiscard]] const EVP_CIPHER* cipher() const;

    [[nodiscard]] int type() const;
    [[nodiscard]] std::string name() const;
    [[nodiscard]] std::size_t block_size() const;
    [[nodiscard]] std::size_t key_length() const;
    [[nodiscard]] std::size_t iv_length() const;
    [[nodiscard]] unsigned long flags() const;
    [[nodiscard]] unsigned long mode() const;
};
typedef std::shared_ptr<SSLCipher> SSLCipherSharedPtr;
} // namespace octo::encryption::ssl

#endif // SSL_MATERIAL_HPP_