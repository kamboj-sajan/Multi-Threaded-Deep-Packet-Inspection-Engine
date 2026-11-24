add_library(dpi_pcap_io
  byte_io.cpp
  pcap_reader.cpp
  pcap_writer.cpp)
add_library(dpi::pcap_io ALIAS dpi_pcap_io)
target_include_directories(dpi_pcap_io PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(dpi_pcap_io PUBLIC dpi_common PRIVATE dpi_warnings)
