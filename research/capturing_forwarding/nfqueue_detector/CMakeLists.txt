# Specify the minimum version for CMake

cmake_minimum_required(VERSION 2.8)
set (CMAKE_CXX_STANDARD 11)

project(nfqueue_detector C CXX)

include_directories(include)

file(GLOB SOURCES "src/*.cpp")

add_executable(det ${SOURCES})

#config file library
#target_link_libraries(det config++)
#threads
#target_link_libraries(det ${CMAKE_THREAD_LIBS_INIT})
