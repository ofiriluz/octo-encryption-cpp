/**
 * @file secure-random.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef SECURE_RANDOM_HPP_
#define SECURE_RANDOM_HPP_

#include <vector>
#include <cstdint>
#include <cstddef>

namespace octo::encryption
{
class SecureRandom
{
  public:
    SecureRandom() = default;
    virtual ~SecureRandom() = default;

    static std::vector<std::uint8_t> generate_random(std::size_t size);
};
} // namespace octo::encryption

#endif // SECURE_RANDOM_HPP_