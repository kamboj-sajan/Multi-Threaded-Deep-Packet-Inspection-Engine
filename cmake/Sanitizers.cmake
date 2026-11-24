# Applies the sanitizer selected by DPI_SANITIZER to every target.
if(NOT DPI_SANITIZER)
  return()
endif()

set(_dpi_allowed "address,undefined" "address" "undefined" "thread")
if(NOT DPI_SANITIZER IN_LIST _dpi_allowed)
  message(FATAL_ERROR "Unsupported DPI_SANITIZER='${DPI_SANITIZER}'. "
                      "Use one of: ${_dpi_allowed}")
endif()

set(_dpi_san_flags -fsanitize=${DPI_SANITIZER} -fno-omit-frame-pointer -g -O1)
if(DPI_SANITIZER MATCHES "undefined")
  # Turn every UB report into a hard failure so ctest catches it.
  list(APPEND _dpi_san_flags -fno-sanitize-recover=all)
endif()

add_compile_options(${_dpi_san_flags})
add_link_options(-fsanitize=${DPI_SANITIZER})
message(STATUS "Sanitizers enabled: ${DPI_SANITIZER}")
