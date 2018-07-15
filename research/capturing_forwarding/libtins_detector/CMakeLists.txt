# Specify the minimum version for CMake

cmake_minimum_required(VERSION 2.8)
set (CMAKE_CXX_STANDARD 11)

project(libtins_det C CXX)

find_package(Threads)

#Bring the headers, such as Student.h into the project
include_directories(include)

#However, the file(GLOB...) allows for wildcard additions:
file(GLOB SOURCES "src/*.cpp")

add_executable(det ${SOURCES})
#inspection library
target_link_libraries(det tins)
#config file library
target_link_libraries(det config++)
#threads
target_link_libraries(det ${CMAKE_THREAD_LIBS_INIT})
