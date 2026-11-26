# Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
cmake_minimum_required(VERSION 3.24)
project(mark47 CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(MARK47_BUILD_GUI "Build the kitui application" ON)

# Linux-only for now (Windows later): system curl, libphonenumber, OpenSSL.
find_package(CURL 7.85 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(libphonenumber CONFIG REQUIRED)

# Modules are UI-free so they can be tested without a window.
add_library(mark47_core STATIC
  src/http.cpp src/util.cpp src/findings.cpp src/case.cpp src/whatsmyname.cpp
  src/modules/registry.cpp src/modules/phone.cpp src/modules/email.cpp
  src/modules/username.cpp src/modules/social.cpp src/modules/music.cpp src/modules/ip.cpp src/modules/domain.cpp src/modules/dork.cpp)
target_include_directories(mark47_core PUBLIC src src/modules third_party)
target_compile_definitions(mark47_core PRIVATE MARK47_DATA_DIR="${CMAKE_SOURCE_DIR}/data")
target_compile_options(mark47_core PRIVATE -Wall -Wextra -Wno-missing-field-initializers)  # Request{.x = ...} idiom
target_link_libraries(mark47_core PUBLIC CURL::libcurl OpenSSL::Crypto
  libphonenumber::phonenumber-shared libphonenumber::geocoding-shared)

if(MARK47_BUILD_GUI)
  set(KITUI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../kitui" CACHE PATH "kitui source tree")
  add_subdirectory("${KITUI_DIR}" kitui)
  add_executable(snitch src/main.cpp)
  target_compile_options(snitch PRIVATE -Wall -Wextra)
  target_link_libraries(snitch PRIVATE mark47_core kitui_app)
endif()

enable_testing()
add_executable(test_core tests/test_core.cpp)
target_link_libraries(test_core PRIVATE mark47_core)
add_test(NAME core COMMAND test_core)

find_package(Python3 QUIET COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  add_executable(test_http tests/test_http.cpp)
  target_link_libraries(test_http PRIVATE mark47_core)
  add_test(NAME http COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/http_fixture.py" $<TARGET_FILE:test_http>)
  set_tests_properties(http PROPERTIES TIMEOUT 25 SKIP_RETURN_CODE 77 ENVIRONMENT "NO_PROXY=127.0.0.1;no_proxy=127.0.0.1")
endif()

# `cmake --install build --prefix ~/.local` -> ~/.local/bin/snitch + ~/.local/share/snitch (data_path() finds it next to bin/)
if(TARGET snitch)
  install(TARGETS snitch)
  install(DIRECTORY data/ DESTINATION share/snitch)
endif()
