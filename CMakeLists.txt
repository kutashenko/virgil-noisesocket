# Copyright (C) 2015-2018 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

cmake_minimum_required(VERSION 3.8)

project(virgil-noisesocket VERSION 0.1)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -g -O0")

########### Address sanitizer ###########
set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_STATIC_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/ext/libnoisesocket")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/ext/virgil-sdk-cpp")

########### virgil-noisesocket ###########
file(GLOB VIRGIL_NOISESOCKET_SRC
        "src/client.cpp"
        "src/server.cpp"
        "src/common.c"
        "src/data.c"
        "src/storage.c"
        )

file(GLOB VIRGIL_NOISESOCKET_INCLUDE
        "include/*.h"
        "include/virgil-noisesocket/*.h"
        )

########### Generate Protobuf structures ###########
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/ext/libnoisesocket/protobuf/nanopb/extra)
find_package(Nanopb REQUIRED)

if (NOT ${NANOPB_FOUND})
    message (FATAL_ERROR "NanoPB not found")
endif()

message (NANOPB_INCLUDE_DIRS = ${NANOPB_INCLUDE_DIRS})
message (PROTOBUF_PROTOC_EXECUTABLE = ${PROTOBUF_PROTOC_EXECUTABLE})
message (NANOPB_GENERATOR_SOURCE_DIR = ${NANOPB_GENERATOR_SOURCE_DIR})

include_directories(${NANOPB_INCLUDE_DIRS})
nanopb_generate_cpp(VIRGIL_PROTO_SRC VIRGIL_PROTO_INCLUDE
        ${CMAKE_CURRENT_SOURCE_DIR}/protobuf/meta.proto
        ${CMAKE_CURRENT_SOURCE_DIR}/protobuf/registration.proto
        )
include_directories(${CMAKE_CURRENT_BINARY_DIR})
set_source_files_properties(${VIRGIL_PROTO_SRC} ${VIRGIL_PROTO_INCLUDE}
        PROPERTIES GENERATED TRUE)

########### Add Virgil NoiseSocket protocol library ###########
add_definitions(-DPB_FIELD_16BIT=1)
add_library(
        ${PROJECT_NAME}

        ${VIRGIL_NOISESOCKET_SRC}
        ${VIRGIL_NOISESOCKET_INCLUDE}

        ${VIRGIL_PROTO_SRC}
        ${VIRGIL_PROTO_INCLUDE}
)

add_dependencies(${PROJECT_NAME} noisesocket virgil_sdk)

 target_include_directories (${PROJECT_NAME}
     PUBLIC
     $<BUILD_INTERFACE:${virgil-noisesocket_SOURCE_DIR}/include>
     $<BUILD_INTERFACE:${virgil-noisesocket_SOURCE_DIR}/include/virgil_noisesocket>
     $<INSTALL_INTERFACE:include>
 )
 find_package (Threads)
 target_link_libraries(${PROJECT_NAME} noisesocket virgil_sdk)

# Build examples
#if (ENABLE_EXAMPLES)
     add_subdirectory (examples/client)
     add_subdirectory (examples/server)
#endif (ENABLE_EXAMPLES)

# Unit tests
#if (ENABLE_TESTING)
    enable_testing ()
    add_subdirectory (tests)
#endif (ENABLE_TESTING)

