# Payload inspection: TLS SNI and HTTP Host extraction.
add_library(dpi_inspect
  hostname.cpp
  tls_sni.cpp
  http_host.cpp)
add_library(dpi::inspect ALIAS dpi_inspect)
target_include_directories(dpi_inspect PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(dpi_inspect PUBLIC dpi_common PRIVATE dpi_warnings)
