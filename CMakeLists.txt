cmake_minimum_required(VERSION 3.5)

# ---- Rust core wiring (blueprint: duckdb-secret-vault / duckdb-nats-rw,
#      originally from ywelsch/duckdb-prql). Corrosion builds the crate from
#      within CMake so CI needs no manual cargo step. ----
set(CORROSION_VERBOSE_OUTPUT ON)
# Pin CMAKE_SYSTEM_PROCESSOR explicitly: corrosion auto-detection drifts on CI
# (nats_rw experience, handbook D4).
set(CMAKE_SYSTEM_PROCESSOR "${CMAKE_SYSTEM_PROCESSOR}" CACHE STRING "" FORCE)
set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

execute_process(
    COMMAND rustup target list --installed
    OUTPUT_VARIABLE RUST_TARGETS
)

# Propagate arch to the Rust build for CI (D4: explicit target, no probing)
set(Rust_CARGO_TARGET "")
if("${OS_NAME}" STREQUAL "linux")
    if ("${OS_ARCH}" STREQUAL "arm64")
        set(Rust_CARGO_TARGET "aarch64-unknown-linux-gnu")
    elseif("${CMAKE_CXX_COMPILER}" MATCHES "aarch64")
        set(Rust_CARGO_TARGET "aarch64-unknown-linux-gnu")
    else()
        string(FIND "${RUST_TARGETS}" "musl" MUSL_TARGET_FOUND)
        if(NOT MUSL_TARGET_FOUND EQUAL -1)
            set(Rust_CARGO_TARGET "x86_64-unknown-linux-musl")
        else()
            set(Rust_CARGO_TARGET "x86_64-unknown-linux-gnu")
        endif()
    endif()
elseif("${OS_NAME}" STREQUAL "osx")
    if ("${OSX_BUILD_ARCH}" STREQUAL "arm64")
        set(Rust_CARGO_TARGET "aarch64-apple-darwin")
    elseif("${OSX_BUILD_ARCH}" STREQUAL "x86_64")
        set(Rust_CARGO_TARGET "x86_64-apple-darwin")
    elseif("${OS_ARCH}" STREQUAL "arm64")
        set(Rust_CARGO_TARGET "aarch64-apple-darwin")
    endif()
elseif(WIN32)
   if (MINGW AND "${OS_ARCH}" STREQUAL "arm64")
       set(Rust_CARGO_TARGET "aarch64-pc-windows-gnu")
   elseif (MINGW AND "${OS_ARCH}" STREQUAL "amd64")
       set(Rust_CARGO_TARGET "x86_64-pc-windows-gnu")
   elseif (MSVC AND "${OS_ARCH}" STREQUAL "arm64")
       set(Rust_CARGO_TARGET "aarch64-pc-windows-msvc")
   elseif (MSVC AND "${OS_ARCH}" STREQUAL "amd64")
       set(Rust_CARGO_TARGET "x86_64-pc-windows-msvc")
   endif()
endif()

if("${Rust_CARGO_TARGET}" STREQUAL "")
  message(FATAL_ERROR "Failed to detect the correct platform")
endif()
message(STATUS "Rust_CARGO_TARGET: ${Rust_CARGO_TARGET}")

set(TARGET_NAME sql_audit)
set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

if(EMSCRIPTEN)
    set(Rust_CARGO_TARGET "wasm32-unknown-emscripten")
endif()

add_subdirectory(corrosion)

corrosion_import_crate(
  MANIFEST_PATH
  rust/Cargo.toml
  CRATES
  sql_audit
  CRATE_TYPES
  staticlib
  FLAGS
  --crate-type=staticlib)

set(EXTENSION_SOURCES src/sql_audit_extension.cpp src/sql_audit_bridge.cpp)

# On MSVC both static and loadable produce .lib and collide - build loadable
# only (MinGW names differ: lib*_extension.a vs lib*.a, no conflict).
if(NOT MSVC)
    build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
endif()
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# The staticlib is self-contained (Rust std + all deps baked in).
if(MSVC)
    # On MSVC the .lib lives in rust-lib/ (corrosion patch avoids the
    # same-name collision with the DLL import library).
    target_link_libraries(${LOADABLE_EXTENSION_NAME}
        ${CMAKE_BINARY_DIR}/extension/${TARGET_NAME}/rust-lib/${TARGET_NAME}.lib
        userenv ntdll ws2_32)
else()
    target_link_libraries(${LOADABLE_EXTENSION_NAME} ${TARGET_NAME}-static)
    target_link_libraries(${EXTENSION_NAME} ${TARGET_NAME}-static)
    if(MINGW)
        # getrandom -> BCryptGenRandom needs bcrypt (toolchain ships libbcrypt.a)
        target_link_libraries(${LOADABLE_EXTENSION_NAME} bcrypt ws2_32 userenv ntdll)
    endif()
endif()

if(NOT MSVC)
install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
endif()
