/**
 * @file encryptor.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef ENCRYPTOR_HPP_
#define ENCRYPTOR_HPP_

#include <string>
#include <memory>
#include "material.hpp"

namespace octo::encryption
{
class Encryptor
{
  public:
    Encryptor() = default;
    virtual ~Encryptor() = default;

    static void secure_zeromem(volatile char* message, size_t size);
    static void secure_zeromem(std::string& message);
    static void secure_zeromem(std::vector<uint8_t>& message);

    virtual std::string encrypt(const std::string& message, const MaterialPtr& material) = 0;
    virtual size_t decrypt(const std::string& message, const MaterialPtr& material, std::string& out_buffer) = 0;
};
typedef std::shared_ptr<Encryptor> EncryptorPtr;
typedef std::unique_ptr<Encryptor> EncryptorUniquePtr;
} // namespace octo::encryption

#endif // ENCRYPTOR_HPP_
