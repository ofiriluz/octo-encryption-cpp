/**
 * @file simple-material.hpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef SIMPLE_MATERIAL_HPP_
#define SIMPLE_MATERIAL_HPP_

#include <string>
#include <memory>
#include <utility>
#include "octo-encryption-cpp/encryptors/material.hpp"
#include "octo-encryption-cpp/encryptors/encryptor.hpp"

namespace octo::encryption
{
class SimpleMaterial : public Material
{
  private:
    std::vector<std::string> materials_;

  public:
    explicit SimpleMaterial(std::vector<std::string> materials) : materials_(std::move(materials))
    {
    }
    ~SimpleMaterial() override
    {
        for (auto& m : materials_)
        {
            Encryptor::secure_zeromem(m);
        }
        materials_.clear();
    }

    [[nodiscard]] std::vector<std::string> generate() const override
    {
        return materials_;
    }
    [[nodiscard]] size_t size() const override
    {
        return materials_.size();
    }
};
} // namespace octo::encryption

#endif // SIMPLE_MATERIAL_HPP_