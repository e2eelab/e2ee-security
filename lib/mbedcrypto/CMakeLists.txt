project(mbedcrypto LANGUAGES C)
include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 17)

option(LINK_WITH_PTHREAD "Explicitly link mbed TLS library to pthread." OFF)
option(LINK_WITH_TRUSTED_STORAGE
       "Explicitly link mbed TLS library to trusted_storage." OFF)

add_subdirectory(include)
add_subdirectory(library)

set(mbedcrypto_target "${MBEDTLS_TARGET_PREFIX}mbedcrypto")
add_library(${mbedcrypto_target} STATIC)
target_sources(${mbedcrypto_target} PRIVATE ${src_files})
target_sources(${mbedcrypto_target} PUBLIC ${src_headers})

set_target_properties(${mbedcrypto_target} PROPERTIES VERSION 2.26.0 SOVERSION
                                                                     2)
target_include_directories(${mbedcrypto_target}
                           PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

install(TARGETS ${mbedcrypto_target}
  CONFIGURATIONS ${CMAKE_BUILD_TYPE}
  EXPORT ${mbedcrypto_target}Targets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES ${src_headers} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mbedcrypto)