/**
 * @file test.cpp
 * @author ofir iluz (iluzofir@gmail.com)
 * @brief
 * @version 0.1
 * @date 2022-08-11
 *
 * @copyright Copyright (c) 2022
 *
 */

#define CATCH_CONFIG_RUNNER
#include <catch2/catch_all.hpp>

int main( int argc, char* argv[] )
{
    int result = Catch::Session().run(argc, argv);
    return result;
}