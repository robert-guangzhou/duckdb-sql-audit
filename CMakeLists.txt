cmake_minimum_required(VERSION 3.5)
project(sql_audit)
set(TARGET_NAME sql_audit)
set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Threads REQUIRED)

# Rust staticlib artifact: .a on unix/MinGW targets, .lib on MSVC targets.
# (Manual cargo step — see README; no corrosion involved.)
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/src/libsql_audit.a")
  set(RUST_STATIC_LIB ${CMAKE_CURRENT_LIST_DIR}/src/libsql_audit.a)
elseif(EXISTS "${CMAKE_CURRENT_LIST_DIR}/src/sql_audit.lib")
  set(RUST_STATIC_LIB ${CMAKE_CURRENT_LIST_DIR}/src/sql_audit.lib)
else()
  message(FATAL_ERROR "Rust staticlib not found in src/ - run cargo build --release in rust/ and copy the artifact (libsql_audit.a / sql_audit.lib) to src/.")
endif()

set(SQL_AUDIT_SOURCES src/sql_audit_extension.cpp)
include(${CMAKE_CURRENT_LIST_DIR}/extension_config.cmake)
build_loadable_extension(${TARGET_NAME} " " ${SQL_AUDIT_SOURCES})

# Platform-specific libs (D3: branch on toolchain family, not WIN32 —
# MinGW must not be caught by MSVC-specific patches).
if(MSVC)
  target_link_libraries(${LOADABLE_EXTENSION_NAME} ${RUST_STATIC_LIB}
      Threads::Threads userenv ntdll ws2_32)
elseif(UNIX)
  target_link_libraries(${LOADABLE_EXTENSION_NAME} ${RUST_STATIC_LIB}
      Threads::Threads dl rt m)
else()
  # MinGW/rtools: not in the supported platform set; link the lib only.
  target_link_libraries(${LOADABLE_EXTENSION_NAME} ${RUST_STATIC_LIB}
      Threads::Threads)
endif()
