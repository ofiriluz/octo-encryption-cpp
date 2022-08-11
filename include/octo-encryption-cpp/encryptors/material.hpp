/**
 * @file material.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef MATERIAL_HPP_
#define MATERIAL_HPP_

#include <string>
#include <memory>
#include <vector>

namespace octo::encryption
{
class Material
{
  public:
    Material() = default;
    virtual ~Material() = default;

    [[nodiscard]] virtual std::vector<std::string> generate() const = 0;
    [[nodiscard]] virtual size_t size() const = 0;
};
typedef std::shared_ptr<Material> MaterialPtr;
typedef std::unique_ptr<Material> MaterialUniquePtr;
} // namespace octo::encryption

#endif // MATERIAL_HPP_