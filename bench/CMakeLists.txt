# Throughput benchmark (plain std::chrono harness, no extra dependency).
add_executable(bench_pipeline bench_pipeline.cpp)
target_link_libraries(bench_pipeline PRIVATE dpi_pipeline dpi_rules dpi_warnings Threads::Threads)
