# ============================================================================
# BIP-39 Seedphrase Generator (C++, airgapped)
# Build:
#   cmake -S . -B build
#   cmake --build build -j
#   ctest --test-dir build
# ============================================================================
cmake_minimum_required(VERSION 3.20)
project(bip39_generator VERSION 1.0.0 LANGUAGES C CXX)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(BIP39_BUILD_TESTS "Build the self-test suite" ON)

# ----------------------------------------------------------------------------
# Hardening (applied to every target of this project)
# ----------------------------------------------------------------------------
add_compile_options(-Wall -Wextra -Wpedantic -fstack-protector-strong)
add_compile_definitions(_FORTIFY_SOURCE=2)
add_link_options(-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack)

# ----------------------------------------------------------------------------
# Embedded wordlist + SHA-256 digest, generated at configure time from
# bip39.txt so the binary can (a) run standalone and (b) verify an external
# bip39.txt against the expected digest.
# ----------------------------------------------------------------------------
file(SHA256 ${CMAKE_SOURCE_DIR}/bip39.txt BIP39_WORDLIST_SHA256)
file(STRINGS ${CMAKE_SOURCE_DIR}/bip39.txt BIP39_WORDLIST_STRINGS)
set(BIP39_WORDLIST_ENTRIES "")
foreach(w IN LISTS BIP39_WORDLIST_STRINGS)
  string(APPEND BIP39_WORDLIST_ENTRIES "    \"${w}\",\n")
endforeach()
list(LENGTH BIP39_WORDLIST_STRINGS BIP39_WORDLIST_COUNT)

set(BIP39_GENERATED_DIR ${CMAKE_BINARY_DIR}/generated)
configure_file(
  src/bip39/wordlist_data.generated.hpp.in
  ${BIP39_GENERATED_DIR}/bip39/wordlist_data.generated.hpp
  @ONLY)

# ----------------------------------------------------------------------------
# libsodium (vendored submodule, compiled statically via autotools)
# ----------------------------------------------------------------------------
include(ExternalProject)

set(LIBSODIUM_ROOT ${CMAKE_BINARY_DIR}/_deps/libsodium/prefix)
set(LIBSODIUM_LIB ${LIBSODIUM_ROOT}/lib/libsodium.a)
set(LIBSODIUM_INCLUDE ${LIBSODIUM_ROOT}/include)

find_program(NPROC NAMES nproc)
if(NPROC)
  execute_process(COMMAND ${NPROC} OUTPUT_VARIABLE BIP39_JOBS)
  string(STRIP "${BIP39_JOBS}" BIP39_JOBS)
else()
  set(BIP39_JOBS 4)
endif()

ExternalProject_Add(libsodium_ext
  PREFIX ${CMAKE_BINARY_DIR}/_deps/libsodium
  SOURCE_DIR ${CMAKE_SOURCE_DIR}/third_party/libsodium
  CONFIGURE_COMMAND ${CMAKE_SOURCE_DIR}/third_party/libsodium/configure
      --prefix=${LIBSODIUM_ROOT}
      --disable-shared
      --enable-static
      --disable-tests
  BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} -j${BIP39_JOBS}
  INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install
  INSTALL_DIR ${LIBSODIUM_ROOT}
  BUILD_IN_SOURCE 0
  BUILD_BYPRODUCTS ${LIBSODIUM_LIB} ${LIBSODIUM_INCLUDE}/sodium.h
)

# ----------------------------------------------------------------------------
# libsecp256k1 (vendored, static, minimal): only the core curve ops
# (secp256k1_ec_pubkey_create / _serialize) are used for BIP-32 / BIP-44
# address derivation. All optional modules, tests, benchmarks and examples are
# disabled to keep the shipped binary as small and dependency-free as possible.
# ----------------------------------------------------------------------------
set(SECP256K1_DISABLE_SHARED ON)
set(SECP256K1_INSTALL OFF)
set(SECP256K1_BUILD_TESTS OFF)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF)
set(SECP256K1_BUILD_CTIME_TESTS OFF)
set(SECP256K1_BUILD_BENCHMARK OFF)
set(SECP256K1_BUILD_EXAMPLES OFF)
set(SECP256K1_ENABLE_MODULE_ECDH OFF)
set(SECP256K1_ENABLE_MODULE_RECOVERY OFF)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS OFF)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG OFF)
set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF)
add_subdirectory(third_party/libsecp256k1 EXCLUDE_FROM_ALL)

# ----------------------------------------------------------------------------
# Core (no GUI) static library: shared by the app and the test suite.
# ----------------------------------------------------------------------------
add_library(bip39_core STATIC
  src/secure_mem/secure_buffer.hpp
  src/entropy/entropy_mixer.cpp
  src/entropy/entropy_mixer.hpp
  src/entropy/entropy_estimator.cpp
  src/entropy/entropy_estimator.hpp
  src/bip39/wordlist.cpp
  src/bip39/wordlist.hpp
  src/bip39/mnemonic.cpp
  src/bip39/mnemonic.hpp
  src/crypto/keccak256.cpp
  src/crypto/keccak256.hpp
  src/crypto/ripemd160.cpp
  src/crypto/ripemd160.hpp
  src/crypto/base58.cpp
  src/crypto/base58.hpp
  src/crypto/pbkdf2.cpp
  src/crypto/pbkdf2.hpp
  src/bip32/bip32.cpp
  src/bip32/bip32.hpp
  src/address/evm.cpp
  src/address/evm.hpp
  src/address/btc.cpp
  src/address/btc.hpp
  src/address/addresses.cpp
  src/address/addresses.hpp
  ${BIP39_GENERATED_DIR}/bip39/wordlist_data.generated.hpp
)
target_include_directories(bip39_core PUBLIC
  ${CMAKE_SOURCE_DIR}/src
  ${BIP39_GENERATED_DIR}
  ${LIBSODIUM_INCLUDE}
)
target_include_directories(bip39_core SYSTEM PUBLIC
  ${LIBSODIUM_INCLUDE}
  ${CMAKE_SOURCE_DIR}/third_party/libsecp256k1/include
)
target_link_libraries(bip39_core PUBLIC ${LIBSODIUM_LIB} secp256k1 pthread)
add_dependencies(bip39_core libsodium_ext)

# ----------------------------------------------------------------------------
# Application (Dear ImGui + GLFW + OpenGL3)
# ----------------------------------------------------------------------------
find_package(OpenGL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLFW REQUIRED IMPORTED_TARGET glfw3)
pkg_check_modules(X11 REQUIRED IMPORTED_TARGET x11)

set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/third_party/imgui)

add_executable(bip39_generator
  src/main.cpp
  src/clipboard/secure_clipboard.cpp
  src/clipboard/secure_clipboard.hpp
  src/ui/app.cpp
  src/ui/app.hpp
  src/ui/screen_entropy_input.cpp
  src/ui/screen_reveal.cpp
  ${IMGUI_DIR}/imgui.cpp
  ${IMGUI_DIR}/imgui_draw.cpp
  ${IMGUI_DIR}/imgui_tables.cpp
  ${IMGUI_DIR}/imgui_widgets.cpp
  ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
  ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)
target_include_directories(bip39_generator PRIVATE
  ${IMGUI_DIR}
  ${IMGUI_DIR}/backends
)
# ImGui is vendored and patched for an airgapped profile:
#  - IMGUI_DISABLE_DEFAULT_SHELL_FUNCTIONS removes the default "open in shell"
#    (fork/execvp) implementation.
#  - The GL loader resolves entry points through glfwGetProcAddress() instead
#    of dlopen() (see IMGL3W_DYNLOAD guard in imgui_impl_opengl3_loader.h).
target_compile_definitions(bip39_generator PRIVATE
  IMGUI_DISABLE_DEFAULT_SHELL_FUNCTIONS
)
target_link_libraries(bip39_generator PRIVATE
  bip39_core
  OpenGL::GL
  PkgConfig::GLFW
  PkgConfig::X11
)

# ----------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------
if(BIP39_BUILD_TESTS)
  enable_testing()

  add_executable(bip39_tests
    tests/test_main.cpp
    tests/test_bip39.cpp
    tests/test_entropy_mixer.cpp
    tests/test_secure_buffer.cpp
    tests/test_wordlist.cpp
    tests/test_addresses.cpp
  )
  target_include_directories(bip39_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/tests
  )
  target_compile_definitions(bip39_tests PRIVATE
    TEST_DATA_DIR="${CMAKE_SOURCE_DIR}/tests"
    WORDSLIST_PATH="${CMAKE_SOURCE_DIR}"
  )
  target_link_libraries(bip39_tests PRIVATE bip39_core)

  add_test(NAME bip39_tests COMMAND bip39_tests)

  # X11 clipboard integration test: skipped automatically when no X display.
  add_executable(bip39_clipboard_test
    tests/clipboard_x11_test.cpp
    src/clipboard/secure_clipboard.cpp
    src/clipboard/secure_clipboard.hpp)
  target_include_directories(bip39_clipboard_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
  target_link_libraries(bip39_clipboard_test PRIVATE
    bip39_core PkgConfig::X11)
  add_test(NAME clipboard_x11 COMMAND bip39_clipboard_test)

  add_test(
    NAME no_network_symbols
    COMMAND ${CMAKE_COMMAND}
      -DBIP39_BINARY=$<TARGET_FILE:bip39_generator>
      -DSCRIPT_DIR=${CMAKE_SOURCE_DIR}/scripts
      -P ${CMAKE_SOURCE_DIR}/scripts/check_no_network.cmake
  )
endif()
