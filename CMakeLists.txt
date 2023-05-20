cmake_minimum_required(VERSION 3.25)
project(Spectre_attack C)

set(CMAKE_C_STANDARD 17)

add_executable(Spectre_attack main.c filePathToAddress.h)
