# Header-only helpers shared by every layer (byte-order loads).
add_library(dpi_common INTERFACE)
add_library(dpi::common ALIAS dpi_common)
target_include_directories(dpi_common INTERFACE ${PROJECT_SOURCE_DIR}/include)
