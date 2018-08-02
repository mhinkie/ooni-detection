# Specify the minimum version for CMake

cmake_minimum_required(VERSION 2.8)
set (CMAKE_CXX_STANDARD 11)

project(nfqueue_detector C CXX)

include_directories(include)

file(GLOB_RECURSE SOURCES src/*.cpp)

find_library(NFNETLINK nfnetlink)
if(NOT NFNETLINK)
  message(FATAL_ERROR "nfnetlink not installed")
endif()

find_library(NETFILTER_QUEUE netfilter_queue)
if(NOT NETFILTER_QUEUE)
  message(FATAL_ERROR "netfilter_queue not installed")
endif()


add_executable(det ${SOURCES})

#config file library
#target_link_libraries(det config++)

#nfqueue
target_link_libraries(det netfilter_queue)

#libtins for parsing
target_link_libraries(det tins)
