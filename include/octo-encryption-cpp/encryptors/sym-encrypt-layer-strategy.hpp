/**
 * @file sym-encrypt-layer-strategy.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#include <string>
#include <cstddef>
#include <cstdint>
#include "material.hpp"
#include "encryptor.hpp"

#ifndef SYM_ENCRYPT_LAYER_STRATEGY_HPP_
#define SYM_ENCRYPT_LAYER_STRATEGY_HPP_

namespace octo::encryption
{
/**
 * @brief Defines a layer-based symetrical encryption strategy
 * Not suitable for binary data in non-character-format
 *
 */
class SymEncryptLayerStrategy
{
  public:
    SymEncryptLayerStrategy() = default;
    virtual ~SymEncryptLayerStrategy() = default;
    /**
     * @brief Encrypt the plain string using the material into ciphered_string
     *
     * @param plain_string
     * @param material
     * @param encryptor
     * @param ciphered_string
     */
    virtual void encrypt(const std::string& plain_string,
                         const MaterialPtr& material,
                         const EncryptorPtr& encryptor,
                         std::string& ciphered_string) const = 0;

    /**
     * @brief Decrypt the ciphered_string using the material into plain_string
     *
     * @param ciphered_string
     * @param material
     * @param encryptor
     * @param plain_string
     * @return std::size_t
     */
    virtual std::size_t decrypt(const std::string& ciphered_string,
                                const MaterialPtr& material,
                                const EncryptorPtr& encryptor,
                                std::string& plain_string) const = 0;
};

/**
 * @brief Defines a 0 layer symetrical encryption strategy (does not encrypt)
 *
 */
class SymEncryptZeroLayerStrategy : public SymEncryptLayerStrategy
{
  public:
    SymEncryptZeroLayerStrategy() = default;
    ~SymEncryptZeroLayerStrategy() override = default;

    /**
     * @brief Encrypt the plain string using the material into ciphered_string
     *
     * @param plain_string
     * @param material
     * @param encryptor
     * @param ciphered_string
     */
    void encrypt(const std::string& plain_string,
                 const MaterialPtr& material,
                 const EncryptorPtr& encryptor,
                 std::string& ciphered_string) const override;

    /**
     * @brief Decrypt the ciphered_string using the material into plain_string
     *
     * @param ciphered_string
     * @param material
     * @param encryptor
     * @param plain_string
     * @return std::size_t
     */
    std::size_t decrypt(const std::string& ciphered_string,
                        const MaterialPtr& material,
                        const EncryptorPtr& encryptor,
                        std::string& plain_string) const override;
};
/**
 * @brief Defines a simple 1 layer encryption strategy
 *
 */
class SymEncryptOneLayerStrategy : public SymEncryptLayerStrategy
{
  public:
    SymEncryptOneLayerStrategy() = default;
    ~SymEncryptOneLayerStrategy() override = default;

    /**
     * @brief Encrypt the plain string using the material into ciphered_string
     *
     * @param plain_string
     * @param material
     * @param encryptor
     * @param ciphered_string
     */
    void encrypt(const std::string& plain_string,
                 const MaterialPtr& material,
                 const EncryptorPtr& encryptor,
                 std::string& ciphered_string) const override;

    /**
     * @brief Decrypt the ciphered_string using the material into plain_string
     *
     * @param ciphered_string
     * @param material
     * @param encryptor
     * @param plain_string
     * @return std::size_t
     */
    std::size_t decrypt(const std::string& ciphered_string,
                        const MaterialPtr& material,
                        const EncryptorPtr& encryptor,
                        std::string& plain_string) const override;
};
} // namespace octo::encryption

#endif // SYM_ENCRYPT_LAYER_STRATEGY_HPP_