cmake_minimum_required(VERSION 2.6)

# Hack: When building against a DR build dir, it doesn't set up an include dir
# for extension headers, so we go ahead and add an include path for the source
# dir of the extensions we use.
include_directories("drmemory/dynamorio/ext/drutil"
                    "drmemory/dynamorio/ext/drmgr"
                    "drmemory/drsyscall"
                    "drmemory/build/drmf/include"
                    )

find_package(DynamoRIO)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

add_library(drmf_drsyscall STATIC IMPORTED)
set_target_properties(drmf_drsyscall PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES "ASM;C"
  IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/drmemory/build/drmf/lib64/release/libdrsyscall.a"
  )

add_library(msandr SHARED msandr.cpp)
target_link_libraries(msandr drmgr drutil drmf_drsyscall drcontainers)

configure_DynamoRIO_client(msandr)
