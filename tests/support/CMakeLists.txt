# Header-only helpers shared by test executables.
add_library(dpi_test_support INTERFACE)
add_library(dpi::test_support ALIAS dpi_test_support)
target_include_directories(dpi_test_support INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
