/**
 * @file base64.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef BASE64_HPP_
#define BASE64_HPP_

#include <string>
#include <cstdint>
#include <cstddef>

namespace octo::encryption
{
class Base64
{
  public:
    Base64() = default;
    virtual ~Base64() = default;

    static std::string base64_encode(const std::string& plain_text);
    static std::string base64_decode(const std::string& encoded_text);
};
} // namespace octo::encryption

#endif // BASE64_HPP_