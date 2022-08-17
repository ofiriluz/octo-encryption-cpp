/**
 * @file digest.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef DIGEST_HPP_
#define DIGEST_HPP_

#include <string>
#include <memory>
#include <vector>
#include <cstdint>
#include <cstddef>

namespace octo::encryption
{
class Digest
{
  public:
    Digest() = default;
    Digest(const Digest&) = default;
    Digest(Digest&&) = default;
    virtual ~Digest() = default;
    Digest& operator=(const Digest&) = default;
    Digest& operator=(Digest&&) = default;

    /**
     * @brief Performs an update to the existing digest
     *
     * @param plain_text
     */
    virtual void update(const std::string& plain_text) = 0;
    virtual void update(const std::vector<char>& plain_text, std::size_t size) = 0;
    virtual void update(const char* plain_text, std::size_t size) = 0;
    virtual void update(const std::uint8_t* plain_text, std::size_t size) = 0;
    /**
     * @brief Resets the digest algorithm
     *
     */
    virtual void reset() = 0;
    /**
     * @brief Finalizes the digest and returns the output hash, should also reset the digest itself afterwards
     *
     * @return std::string
     */
    virtual std::string finalize() = 0;
    /**
     * @brief Getter for the digest length
     *
     * @return std::size_t
     */
    virtual std::size_t length() = 0;
    /**
     * @brief Clones the current digest
     *
     * @return
     */
    virtual std::unique_ptr<Digest> clone() = 0;
};
typedef std::shared_ptr<Digest> DigestSharedPtr;
} // namespace octo::encryption

#endif // DIGEST_HPP_