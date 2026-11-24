# Interface target that carries our warning policy. Link it PRIVATE into
# every first-party target.
add_library(dpi_warnings INTERFACE)
target_compile_options(dpi_warnings INTERFACE
  -Wall -Wextra -Wpedantic -Werror
  -Wshadow -Wnon-virtual-dtor)
