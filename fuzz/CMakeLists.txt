# libFuzzer targets (Clang on Linux; Apple's clang ships no libFuzzer).
# Build:  cmake --preset fuzz && cmake --build --preset fuzz
# Run:    build/fuzz/fuzz/fuzz_packet_parser fuzz/corpus/packet_parser -max_total_time=60
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "DPI_BUILD_FUZZ requires Clang (libFuzzer)")
endif()

foreach(target fuzz_packet_parser fuzz_inspect)
  add_executable(${target} ${target}.cpp)
  target_link_options(${target} PRIVATE -fsanitize=fuzzer)
  target_link_libraries(${target} PRIVATE dpi_warnings)
endforeach()
target_link_libraries(fuzz_packet_parser PRIVATE dpi_packet_parser)
target_link_libraries(fuzz_inspect PRIVATE dpi_inspect)
