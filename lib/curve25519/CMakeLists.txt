project(curve25519 LANGUAGES C)
include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 17)

set(ed25519_SRCS
    curve25519-donna.c
    ed25519/fe_0.c
    ed25519/fe_1.c
    ed25519/fe_add.c
    ed25519/fe_cmov.c
    ed25519/fe_copy.c
    ed25519/fe_frombytes.c
    ed25519/fe_invert.c
    ed25519/fe_isnegative.c
    ed25519/fe_isnonzero.c
    ed25519/fe_mul.c
    ed25519/fe_neg.c
    ed25519/fe_pow22523.c
    ed25519/fe_sq.c
    ed25519/fe_sq2.c
    ed25519/fe_sub.c
    ed25519/fe_tobytes.c
    ed25519/ge_add.c
    ed25519/ge_double_scalarmult.c
    ed25519/ge_frombytes.c
    ed25519/ge_madd.c
    ed25519/ge_msub.c
    ed25519/ge_p1p1_to_p2.c
    ed25519/ge_p1p1_to_p3.c
    ed25519/ge_p2_0.c
    ed25519/ge_p2_dbl.c
    ed25519/ge_p3_0.c
    ed25519/ge_p3_dbl.c
    ed25519/ge_p3_to_cached.c
    ed25519/ge_p3_to_p2.c
    ed25519/ge_p3_tobytes.c
    ed25519/ge_precomp_0.c
    ed25519/ge_scalarmult_base.c
    ed25519/ge_sub.c
    ed25519/ge_tobytes.c
    ed25519/open.c
    ed25519/sc_muladd.c
    ed25519/sc_reduce.c
    ed25519/sign.c
    ed25519/additions/compare.c
    ed25519/additions/curve_sigs.c
    ed25519/additions/elligator.c
    ed25519/additions/fe_isequal.c
    ed25519/additions/fe_isreduced.c
    ed25519/additions/fe_mont_rhs.c
    ed25519/additions/fe_montx_to_edy.c
    ed25519/additions/fe_sqrt.c
    ed25519/additions/ge_isneutral.c
    ed25519/additions/ge_montx_to_p3.c
    ed25519/additions/ge_neg.c
    ed25519/additions/ge_p3_to_montx.c
    ed25519/additions/ge_scalarmult.c
    ed25519/additions/ge_scalarmult_cofactor.c
    ed25519/additions/keygen.c
    ed25519/additions/open_modified.c
    ed25519/additions/sc_clamp.c
    ed25519/additions/sc_cmov.c
    ed25519/additions/sc_neg.c
    ed25519/additions/sign_modified.c
    ed25519/additions/utility.c
    ed25519/additions/generalized/ge_p3_add.c
    ed25519/additions/generalized/gen_eddsa.c
    ed25519/additions/generalized/gen_labelset.c
    ed25519/additions/generalized/gen_veddsa.c
    ed25519/additions/generalized/gen_x.c
    ed25519/additions/generalized/point_isreduced.c
    ed25519/additions/generalized/sc_isreduced.c
    ed25519/additions/xeddsa.c
    ed25519/additions/zeroize.c
    ed25519/nacl_sha512/blocks.c
    ed25519/nacl_sha512/hash.c)

set(ed25519_headers
    curve25519-donna.h
    ed25519/fe.h
    ed25519/ge_add.h
    ed25519/ge_madd.h
    ed25519/ge_msub.h
    ed25519/ge_p2_dbl.h
    ed25519/ge_sub.h
    ed25519/ge.h
    ed25519/pow22523.h
    ed25519/pow225521.h
    ed25519/sc.h
    ed25519/sqrtm1.h
    ed25519/additions/compare.h
    ed25519/additions/crypto_additions.h
    ed25519/additions/crypto_hash_sha512.h
    ed25519/additions/curve_sigs.h
    ed25519/additions/keygen.h
    ed25519/additions/utility.h
    ed25519/additions/xeddsa.h
    ed25519/additions/zeroize.h
    ed25519/additions/generalized/gen_crypto_additions.h
    ed25519/additions/generalized/gen_constants.h
    ed25519/additions/generalized/gen_eddsa.h
    ed25519/additions/generalized/gen_labelset.h
    ed25519/additions/generalized/gen_veddsa.h
    ed25519/additions/generalized/gen_x.h)

add_library(curve25519 STATIC)

target_sources(curve25519 PRIVATE ${ed25519_SRCS})
target_sources(curve25519 PUBLIC ${ed25519_headers})

target_include_directories(
  curve25519
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
         $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ed25519>
         $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ed25519/additions>
         $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ed25519/nacl_includes>
         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_compile_options(
  curve25519
  PUBLIC "$<$<COMPILE_LANG_AND_ID:C,AppleClang,Clang>:-Wno-unused-variable>"
         "$<$<COMPILE_LANG_AND_ID:C,AppleClang,Clang>:-Wno-unused-function>"
         "$<$<COMPILE_LANG_AND_ID:C,AppleClang,Clang>:-Wno-shadow>"
         "$<$<COMPILE_LANG_AND_ID:C,AppleClang,Clang>:-Wno-shorten-64-to-32>"
         "$<$<COMPILE_LANG_AND_ID:C,GNU>:-Wno-sign-compare>")

if(GCC_WARN_SIGN_CONVERSION)
  target_compile_options(
    curve25519 PUBLIC "$<$<COMPILE_LANG_AND_ID:C,GNU>:-Wno-sign-conversion>")
endif(GCC_WARN_SIGN_CONVERSION)

install(TARGETS curve25519
  CONFIGURATIONS ${CMAKE_BUILD_TYPE}
  EXPORT curve25519Targets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY . DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/curve25519 FILES_MATCHING PATTERN "*.h")
