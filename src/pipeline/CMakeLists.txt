add_library(dpi_pipeline
  stats.cpp
  stages.cpp
  flow_inspector.cpp
  sequential.cpp
  pipeline.cpp
  report.cpp)
add_library(dpi::pipeline ALIAS dpi_pipeline)
target_include_directories(dpi_pipeline PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(dpi_pipeline
  PUBLIC dpi_pcap_io dpi_packet_parser dpi_flow dpi_inspect dpi_classifier dpi_concurrency
  PRIVATE dpi_warnings)
