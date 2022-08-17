/**
 * @file sym-encrypt-layer-strategy.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-encryption-cpp/encryptors/sym-encrypt-layer-strategy.hpp"

#include <stdexcept>

namespace octo::encryption
{
void SymEncryptZeroLayerStrategy::encrypt(const std::string& plain_string,
                                          const MaterialPtr& material,
                                          const EncryptorPtr& encryptor,
                                          std::string& ciphered_string) const
{
    ciphered_string = plain_string;
}

std::size_t SymEncryptZeroLayerStrategy::decrypt(const std::string& ciphered_string,
                                                 const MaterialPtr& material,
                                                 const EncryptorPtr& encryptor,
                                                 std::string& plain_string) const
{
    plain_string = ciphered_string;
    return plain_string.size();
}

void SymEncryptOneLayerStrategy::encrypt(const std::string& plain_string,
                                         const MaterialPtr& material,
                                         const EncryptorPtr& encryptor,
                                         std::string& ciphered_string) const
{
    if (!material || !encryptor)
    {
        throw std::runtime_error("Cannot encrypt with one layer, material or encryptor are invalid");
    }

    ciphered_string = encryptor->encrypt(plain_string, material);
}

std::size_t SymEncryptOneLayerStrategy::decrypt(const std::string& ciphered_string,
                                                const MaterialPtr& material,
                                                const EncryptorPtr& encryptor,
                                                std::string& plain_string) const
{
    if (!material || !encryptor)
    {
        throw std::runtime_error("Cannot decrypt with one layer, material or encryptor are invalid");
    }

    return encryptor->decrypt(ciphered_string, material, plain_string);
}
} // namespace octo::encryption