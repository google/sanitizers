cmake_minimum_required(VERSION 2.6)

find_package(DynamoRIO)
find_package(DrMemoryFramework)


add_library(msandr SHARED msandr.cpp)
configure_DynamoRIO_client(msandr)

use_DynamoRIO_extension(msandr drutil)
use_DynamoRIO_extension(msandr drmgr)
use_DynamoRIO_extension(msandr drsyscall)
