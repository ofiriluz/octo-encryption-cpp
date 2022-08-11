/**
 * @file secure-random.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "octo-encryption-cpp/secure-random.hpp"
#include <openssl/rand.h>
#include <vector>

namespace octo::encryption
{
std::vector<uint8_t> SecureRandom::generate_random(size_t size)
{
    if (size == 0)
    {
        return std::vector<uint8_t>();
    }
    std::vector<uint8_t> v(size, 0);
    if (!RAND_bytes(&v[0], size))
    {
        return std::vector<uint8_t>();
    }
    return v;
}
} // namespace octo::encryption