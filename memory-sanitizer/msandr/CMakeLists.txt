cmake_minimum_required(VERSION 2.6)

# Hack: When building against a DR build dir, it doesn't set up an include dir
# for extension headers, so we go ahead and add an include path for the source
# dir of the extensions we use.
include_directories("dr/ext/drutil" "dr/ext/drmgr")

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

add_library(msandr SHARED msandr.cpp)

target_link_libraries(msandr drmgr drutil)

configure_DynamoRIO_client(msandr)
