cmake_minimum_required(VERSION 2.6)

# Hack: When building against a DR build dir, it doesn't set up an include dir
# for extension headers, so we go ahead and add an include path for the source
# dir of the extensions we use.
include_directories("drmemory/dynamorio/ext/drutil"
                    "drmemory/dynamorio/ext/drmgr"
                    "drmemory/drsyscall"
                    "drmemory/build/drmf/include"
                    )

add_library(msandr SHARED msandr.cpp)

find_package(DynamoRIO)

find_package(DrMemoryFramework)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

use_DynamoRIO_extension(msandr drmf_drsyscall drmgr drutil)

target_link_libraries(msandr drmgr drutil)

configure_DynamoRIO_client(msandr)
