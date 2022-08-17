/**
 * @file ssl-encryptor.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef SSL_ENCRYPTOR_HPP_
#define SSL_ENCRYPTOR_HPP_

#include "octo-encryption-cpp/encryptors/encryptor.hpp"
#include "octo-encryption-cpp/encryptors/material.hpp"
#include "ssl-cipher.hpp"

namespace octo::encryption::ssl
{
class SSLEncryptor : public Encryptor
{
  private:
    SSLCipherSharedPtr ssl_cipher_;

  private:
    std::unique_ptr<std::uint8_t[]> generate_key_material(const MaterialPtr& material);

  public:
    SSLEncryptor(const SSLCipherSharedPtr& cipher);
    ~SSLEncryptor() override = default;

    std::string encrypt(const std::string& message, const MaterialPtr& material) override;
    std::size_t decrypt(const std::string& message, const MaterialPtr& material, std::string& out_buffer) override;
};
} // namespace octo::encryption::ssl

#endif // SSL_ENCRYPTOR_HPP_
