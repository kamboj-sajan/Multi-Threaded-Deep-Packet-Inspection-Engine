add_library(dpi_packet_parser packet_parser.cpp)
add_library(dpi::packet_parser ALIAS dpi_packet_parser)
target_include_directories(dpi_packet_parser PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(dpi_packet_parser PUBLIC dpi_common PRIVATE dpi_warnings)
