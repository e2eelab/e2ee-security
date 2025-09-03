# ##############################################################################
#
# Copyright © 2021 Academia Sinica. All Rights Reserved.
#
# This file is part of E2EE Security.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# E2EE Security is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# E2EE Security.  If not, see <http://www.gnu.org/licenses/>.
#
# ##############################################################################

cmake_minimum_required(VERSION 3.21)
project(
  e2ees
  LANGUAGES CXX C)

cmake_policy(SET CMP0009 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0079 NEW)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 17)

include(GNUInstallDirs)

option(E2EES_BUILD_PROTOBUF "Build protobuf" ON)
option(E2EES_TESTS "Build e2ees tests" ON)

set(EXTERNAL_LIB_DIR "${CMAKE_CURRENT_BINARY_DIR}/lib")

# library path
set(lib_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(curve25519_DIR "${lib_DIR}/curve25519")
set(mbedcrypto_DIR "${lib_DIR}/mbedcrypto")
set(protobuf_DIR "${lib_DIR}/protobuf")
set(protobuf-c_DIR "${lib_DIR}/protobuf-c")
set(pqclean_DIR "${lib_DIR}/PQClean")

# protobuf flags
set(protobuf_BUILD_SHARED_LIBS OFF)
set(protobuf_BUILD_PROTOC_BINARIES OFF)
set(protobuf_BUILD_LIBPROTOC OFF)
set(protobuf_BUILD_TESTS OFF)

# set protoc tool path, ex: "/usr/local/bin/protoc"
find_program(PROTOC_EXECUTABLE protoc REQUIRED)
if(NOT PROTOC_EXECUTABLE)
  message(FATAL_ERROR "protoc excutable not found! Please install protoc")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

add_subdirectory(${curve25519_DIR} ${EXTERNAL_LIB_DIR}/curve25519)
add_subdirectory(${mbedcrypto_DIR} ${EXTERNAL_LIB_DIR}/mbedcrypto)
add_subdirectory(${pqclean_DIR} ${EXTERNAL_LIB_DIR}/PQClean)
if(E2EES_BUILD_PROTOBUF)
  add_subdirectory(${protobuf_DIR})
endif()

# Patch absl bug https://github.com/abseil/abseil-cpp/commit/26ee072e14dea17fa8870d47cd7e8b4cc1c95e93
#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/AbseilConfigureCopts.cmake
#               ${lib_DIR}/protobuf/third_party/abseil-cpp/absl/copts/AbseilConfigureCopts.cmake COPYONLY)

# Patch Protobuf-c bug https://github.com/protobuf-c/protobuf-c/pull/482
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/protobuf-c.cmake
               ${protobuf-c_DIR}/CMakeLists.txt COPYONLY)
add_subdirectory(${protobuf-c_DIR} ${EXTERNAL_LIB_DIR}/protobuf-c)

file(GLOB e2ees_src ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
file(GLOB src_headers ${CMAKE_CURRENT_SOURCE_DIR}/include/e2ees/*.h)

set(PROTO_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/protos/src)
set(PROTO_DIS_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto-gen)
file(MAKE_DIRECTORY ${PROTO_DIS_DIR}/e2ees)

file(GLOB e2ees_PROTOS ${PROTO_SRC_DIR}/e2ees/*.proto)

set(PROTOBUF_PROTOC_EXECUTABLE
    "/usr/local/bin/protoc"
    CACHE STRING "Protoc binary on host")

set(proto_gen_src "")
set(proto_gen_header "")

foreach(proto ${e2ees_PROTOS})
  get_filename_component(proto_name ${proto} NAME_WE)
  message(STATUS "  convert => ${proto}")
  execute_process(
    COMMAND
      ${PROTOC_EXECUTABLE} -I=e2ees --proto_path=${PROTO_SRC_DIR}
      --c_out=${PROTO_DIS_DIR}/e2ees ${proto_name}.proto
    RESULT_VARIABLE rv
    OUTPUT_VARIABLE protoc_output
    WORKING_DIRECTORY ${PROTO_SRC_DIR})
  list(APPEND proto_gen_src ${PROTO_DIS_DIR}/e2ees/${proto_name}.pb-c.c)
  list(APPEND proto_gen_header ${PROTO_DIS_DIR}/e2ees/${proto_name}.pb-c.h)

  # Optional, but that can show the user if something have gone wrong with the
  # proto generation
  if(${rv})
    message("Generation of data model returned ${rv}")
  endif()
endforeach(proto)

# Target: e2ees_static
add_library(e2ees_static STATIC ${e2ees_src} ${src_headers}
                                  ${proto_gen_src} ${proto_gen_header})

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_definitions(e2ees_static PRIVATE ENABLE_TRACE)
endif()

add_dependencies(e2ees_static curve25519 mbedcrypto protobuf::libprotobuf
                  protobuf-c)

target_include_directories(
  e2ees_static
  PUBLIC $<BUILD_INTERFACE:${PROTO_DIS_DIR}>
          $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
          $<BUILD_INTERFACE:${protobuf-c_DIR}>
          $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE ${lib_DIR} ${lib_DIR}/curve25519 ${lib_DIR}/curve25519/ed25519
          ${lib_DIR}/curve25519/ed25519/additions
          ${lib_DIR}/curve25519/ed25519/nacl_includes)

set_target_properties(
  e2ees_static
  PROPERTIES OUTPUT_NAME "e2ees"
              WINDOWS_EXPORT_ALL_SYMBOLS ON
              ARCHIVE_OUTPUT_DIRECTORY
              ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}
              LIBRARY_OUTPUT_DIRECTORY
              ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}
              RUNTIME_OUTPUT_DIRECTORY
              ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})

target_link_libraries(e2ees_static PUBLIC mbedcrypto curve25519 pqclean
                                            protobuf::libprotobuf protobuf-c)

# Install
install(TARGETS e2ees_static
  EXPORT e2ees-targets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  #INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  #PRIVATE_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/.
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING
    PATTERN "*.h")

install(
    DIRECTORY ${PROTO_DIS_DIR}/.
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING
    PATTERN "*.h")

if(E2EES_TESTS)
  add_subdirectory(tests)
endif()
