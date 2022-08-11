/**
 * @file encryptor.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-encryption-cpp/encryptors/encryptor.hpp"

namespace octo::encryption
{
void Encryptor::secure_zeromem(volatile char* message, size_t size)
{
    if (message == nullptr)
    {
        return;
    }

    for (size_t i = 0; i < size; ++i)
    {
        *(((volatile char*)message) + i) ^= *(((volatile char*)message) + i);
    }
}

void Encryptor::secure_zeromem(std::string& message)
{
    secure_zeromem(reinterpret_cast<volatile char*>(&message[0]), message.size());
}

void Encryptor::secure_zeromem(std::vector<uint8_t>& message)
{
    secure_zeromem(reinterpret_cast<volatile char*>(&message[0]), message.size());
}
} // namespace octo::encryption
