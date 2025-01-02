cmake_minimum_required(VERSION 3.27)
project(CryptographicAlgortihms)

set(CMAKE_CXX_STANDARD 23)

include_directories(include)

file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(CryptographicAlgortihms main.cpp
        include/cryptography.h
        src/rsa.cpp
        include/rsa.h)
