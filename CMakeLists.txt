cmake_minimum_required(VERSION 3.25)
project(dpi_engine VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(DPI_BUILD_TESTS "Build unit and integration tests" ON)
option(DPI_BUILD_BENCH "Build benchmarks" OFF)
option(DPI_BUILD_FUZZ "Build libFuzzer targets (Clang only)" OFF)
set(DPI_SANITIZER "" CACHE STRING
    "Sanitizers to build with: empty, 'address,undefined' or 'thread'")

# Sanitizer flags are applied globally (including to GoogleTest) because
# ThreadSanitizer only reports reliably when every translation unit is
# instrumented.
include(cmake/Sanitizers.cmake)
# Warning flags are applied per target through dpi_warnings so that
# third-party code never breaks our -Werror build.
include(cmake/Warnings.cmake)

find_package(Threads REQUIRED)

# Fuzzing needs coverage instrumentation in the libraries under test, not
# just in the fuzz targets, so it is enabled before any library is defined.
if(DPI_BUILD_FUZZ)
  add_compile_options(-fsanitize=fuzzer-no-link)
endif()

add_subdirectory(src)

if(DPI_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(DPI_BUILD_BENCH)
  add_subdirectory(bench)
endif()

if(DPI_BUILD_FUZZ)
  add_subdirectory(fuzz)
endif()
