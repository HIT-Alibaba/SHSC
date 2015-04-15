cmake_minimum_required(VERSION 2.6)

project(SHSC CXX)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

set(CXX_FLAGS
    -g
    -Wall
    -march=native
    -rdynamic
    -std=c++0x
)

string(REPLACE ";" " " CMAKE_CXX_FLAGS "${CXX_FLAGS}")

set(CMAKE_CXX_COMPILER "g++")
set(CMAKE_CXX_FLAGS_DEBUG "-O2")

string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE)
message(STATUS "CXX_FLAGS = " ${CMAKE_CXX_FLAGS} " " ${CMAKE_CXX_FLAGS_${BUILD_TYPE}})

find_package(Boost REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})
include_directories(/home/jason/Downloads/node-v0.12.0/deps/openssl/openssl/include/)
include_directories(~/cpp/rapidjson/include)
include_directories(${PROJECT_SOURCE_DIR}/src)

set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin) 

file(GLOB_RECURSE SOURCE 
     ${CMAKE_CURRENT_SOURCE_DIR}
     ${CMAKE_CURRENT_SOURCE_DIR}/src/share/*.cc
     ${CMAKE_CURRENT_SOURCE_DIR}/src/network/*.cc
     ${CMAKE_CURRENT_SOURCE_DIR}/src/image/*.cc
)

add_library(shsc ${SOURCE})
target_link_libraries(shsc pthread rt crypto)
set_target_properties(shsc PROPERTIES OUTPUT_NAME shsc)
install(TARGETS shsc DESTINATION lib)

add_subdirectory(test)
