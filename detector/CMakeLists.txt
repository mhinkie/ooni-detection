# Specify the minimum version for CMake
cmake_minimum_required(VERSION 3.5)
set (CMAKE_CXX_STANDARD 11)


###############REQUIREMENTS###############
find_library(NFNETLINK nfnetlink)
if(NOT NFNETLINK)
  message(FATAL_ERROR "nfnetlink not installed")
endif()

find_library(NETFILTER_QUEUE netfilter_queue)
if(NOT NETFILTER_QUEUE)
  message(FATAL_ERROR "netfilter_queue not installed")
endif()

find_package(Boost)
if(NOT Boost_FOUND)
  message(FATAL_ERROR "boost not installed")
endif()

###############FILES###############
project(nfqueue_detector C CXX)

include_directories(include)

file(GLOB_RECURSE SOURCES src/*.cpp)

include_directories(${Boost_INCLUDE_DIRS})

###############EXECUTABLE###############
add_executable(det ${SOURCES})

###############FLAGS###############
#debug flag
SET( CMAKE_BUILD_TYPE Debug)

#trace flag
target_compile_definitions(det PUBLIC ISTRACE)



###############LINKER###############
#config file library
#target_link_libraries(det config++)

#nfqueue
target_link_libraries(det netfilter_queue)

#libtins for parsing
target_link_libraries(det tins)

#Boost
target_link_libraries(det boost_thread)
target_link_libraries(det boost_system)

#dns (not required - using getaddrinfo)
#target_link_libraries(det resolv)
