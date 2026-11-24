add_library(dpi_flow
  five_tuple.cpp
  tcp_tracker.cpp
  flow_table.cpp)
add_library(dpi::flow ALIAS dpi_flow)
target_include_directories(dpi_flow PUBLIC ${PROJECT_SOURCE_DIR}/include)
# The flow layer consumes parser output (PacketTuple) and the shared types.
target_link_libraries(dpi_flow PUBLIC dpi_packet_parser dpi_common PRIVATE dpi_warnings)
