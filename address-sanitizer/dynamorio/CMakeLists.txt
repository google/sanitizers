cmake_minimum_required(VERSION 2.6)

add_library(dr_asan SHARED dr_asan.cpp)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

use_DynamoRIO_extension(dr_asan drsyms) 

configure_DynamoRIO_client(dr_asan)
