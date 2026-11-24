include(FetchContent)

# GoogleTest is pinned by tag and checksum for reproducible builds. SYSTEM
# keeps its headers out of our -Werror warning set.
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.tar.gz
  URL_HASH SHA256=65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  SYSTEM)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

# dpi_add_test(<name> SOURCES <files...> LIBS <targets...>)
# Builds one test executable per library and registers each TEST() with
# ctest individually.
function(dpi_add_test name)
  cmake_parse_arguments(ARG "" "" "SOURCES;LIBS" ${ARGN})
  add_executable(${name} ${ARG_SOURCES})
  target_link_libraries(${name} PRIVATE ${ARG_LIBS} GTest::gtest_main dpi_warnings)
  target_compile_definitions(${name} PRIVATE
    DPI_TEST_DATA_DIR="${PROJECT_SOURCE_DIR}/tests/data")
  # PRE_TEST discovery avoids running (possibly sanitized) binaries at
  # build time.
  gtest_discover_tests(${name} DISCOVERY_MODE PRE_TEST)
endfunction()

add_subdirectory(support)
add_subdirectory(pcap_io)
add_subdirectory(parser)
add_subdirectory(flow)
add_subdirectory(inspect)
add_subdirectory(classifier)
add_subdirectory(rules)
add_subdirectory(concurrency)
add_subdirectory(pipeline)
add_subdirectory(app)
add_subdirectory(integration)
