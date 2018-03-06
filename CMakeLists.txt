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

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -g -O0")

########### Address sanitizer ###########
set (CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_STATIC_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/ext/libnoisesocket")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/ext/virgil-sdk-cpp")

########### virgil-noisesocket ###########
file(GLOB VIRGIL_NOISESOCKET_SRC
        "src/client.c"
        "src/server.c"
        )

file(GLOB VIRGIL_NOISESOCKET_INCLUDE
        "include/virgil-noisesocket/*.h"
        )

add_library(
        ${PROJECT_NAME}

         ${VIRGIL_NOISESOCKET_SRC}
         ${VIRGIL_NOISESOCKET_INCLUDE}
)

add_dependencies(${PROJECT_NAME} noisesocket)

# target_include_directories (${PROJECT_NAME}
#     PUBLIC
#     $<BUILD_INTERFACE:${noisesocket_SOURCE_DIR}/ext/noise/src>
#     $<BUILD_INTERFACE:${noisesocket_SOURCE_DIR}/ext/noise/protocol>
#     $<BUILD_INTERFACE:${noisesocket_SOURCE_DIR}/include>
#     $<BUILD_INTERFACE:${noisesocket_SOURCE_DIR}/include/noisesocket>
#     $<BUILD_INTERFACE:${noisesocket_SOURCE_DIR}/include/noisesocket/backends>
#     $<BUILD_INTERFACE:${noisesocket_SOURCE_DIR}/include/noisesocket/private>
#     $<INSTALL_INTERFACE:include>
#     sodium_INCLUDE_DIR
# )
# find_package (Threads)
 target_link_libraries(${PROJECT_NAME} noisesocket)

# Build examples
#if (ENABLE_EXAMPLES)
     add_subdirectory (examples/client)
     add_subdirectory (examples/server)
#endif (ENABLE_EXAMPLES)

