/**
 * @file encrypted-string.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef SSL_ENCRYPTED_STRING_HPP_
#define SSL_ENCRYPTED_STRING_HPP_

#include <string>
#include <memory>
#include <vector>
#include <stdexcept>

#include "encryptor.hpp"
#include "sym-encrypt-layer-strategy.hpp"
#include "material.hpp"

namespace octo::encryption
{
template <class EncryptionStrategy>
class EncryptedString
{
    static_assert(std::is_base_of<SymEncryptLayerStrategy, EncryptionStrategy>::value,
                  "strategy must inherit from SymEncryptLayerStrategy");

  protected:
    bool is_plain_exists_;
    bool is_initialized_;
    std::string plain_string_;
    std::string ciphered_string_;

    MaterialPtr material_;
    EncryptorPtr encryptor_;
    EncryptionStrategy encryption_strategy_;

  public:
    // Remove copy constructor and copy operators so it isn't copy-able
    EncryptedString(const EncryptedString&) = delete;
    virtual EncryptedString& operator=(const EncryptedString&) = delete;
    virtual EncryptedString& operator=(EncryptedString&&) = delete;
    EncryptedString(EncryptedString&& other) = delete;

  public:
    EncryptedString(const std::string& ciphered_string,
                    const MaterialPtr& material = MaterialPtr(),
                    const EncryptorPtr& encryptor = EncryptorPtr())
        : is_plain_exists_(false),
          is_initialized_(true),
          plain_string_(""),
          ciphered_string_(ciphered_string),
          material_(material),
          encryptor_(encryptor)
    {
    }

    EncryptedString(const EncryptorPtr& encryptor = EncryptorPtr())
        : is_plain_exists_(false),
          is_initialized_(false),
          plain_string_(""),
          ciphered_string_(""),
          encryptor_(encryptor)
    {
    }

    virtual ~EncryptedString()
    {
        destruct();
        Encryptor::secure_zeromem(ciphered_string_);
        ciphered_string_ = "";
    }

    /**
     * @brief Set a new EncryptedString by encrypting a plain_string using the material
     *
     * @param plain_string
     * @param material
     */
    void set(const std::string& plain_string, const MaterialPtr& material = MaterialPtr());

    /**
     * @brief Decrypt and return a plain string reference. Return value should not be copied!
     *
     * @return const std::string&
     */
    const std::string& get();

    /**
     * @brief View only string reference of the current text, does not guarantee the text exists or was decrypted
     *
     * @return
     */
    [[nodiscard]] std::string_view get() const;

    /**
     * @brief Swaps the current material with a new given material
     *
     * @param material
     */
    void swap(const MaterialPtr& material);

    inline const std::string& cipher()
    {
        return ciphered_string_;
    }

    inline MaterialPtr material()
    {
        return material_;
    }

    inline EncryptorPtr encryptor()
    {
        return encryptor_;
    }

    inline bool is_initialized()
    {
        return is_initialized_;
    }

    void destruct()
    {
        if (is_plain_exists_)
        {
            Encryptor::secure_zeromem(plain_string_);
            plain_string_ = "";
            is_plain_exists_ = false;
        }
    }
};

template <class EncryptionStrategy>
void EncryptedString<EncryptionStrategy>::set(const std::string& plain_string, const MaterialPtr& material)
{
    material_ = material;
    Encryptor::secure_zeromem(ciphered_string_);
    encryption_strategy_.encrypt(plain_string, material, encryptor_, ciphered_string_);
    is_initialized_ = true;
    destruct();
}

template <class EncryptionStrategy>
const std::string& EncryptedString<EncryptionStrategy>::get()
{
    // use the data member instead of decrypting again
    if (is_plain_exists_)
    {
        return plain_string_;
    }

    // validate the cipher was set
    if (!is_initialized_)
    {
        throw std::runtime_error("Error retrieving plain from non-initialized EncryptedString");
    }

    encryption_strategy_.decrypt(ciphered_string_, material_, encryptor_, plain_string_);
    is_plain_exists_ = true;

    return plain_string_;
}

template <class EncryptionStrategy>
std::string_view EncryptedString<EncryptionStrategy>::get() const
{
    if (is_plain_exists_)
    {
        return plain_string_;
    }
    return ciphered_string_;
}

template <class EncryptionStrategy>
void EncryptedString<EncryptionStrategy>::swap(const MaterialPtr& material)
{
    if (!is_plain_exists_)
    {
        encryption_strategy_.decrypt(ciphered_string_, material_, encryptor_, plain_string_);
        is_plain_exists_ = true;
    }
    set(plain_string_, material);
}

// Define default SimpleEncryptedString with 1Layer encryption
typedef EncryptedString<SymEncryptOneLayerStrategy> SingleEncryptedString;
typedef std::shared_ptr<SingleEncryptedString> SingleEncryptedStringSharedPtr;
typedef std::unique_ptr<SingleEncryptedString> SingleEncryptedStringUniquePtr;

// Define default NotEncryptedString with NO encryption
typedef EncryptedString<SymEncryptZeroLayerStrategy> SecureString;
typedef std::shared_ptr<SecureString> SecureStringSharedPtr;
typedef std::unique_ptr<SecureString> SecureStringUniquePtr;
} // namespace octo::encryption

#endif // ENCRYPTED_STRING_HPP_