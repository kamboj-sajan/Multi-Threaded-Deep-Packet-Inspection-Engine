# Header-only: BoundedBlockingQueue is a template.
add_library(dpi_concurrency INTERFACE)
add_library(dpi::concurrency ALIAS dpi_concurrency)
target_include_directories(dpi_concurrency INTERFACE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(dpi_concurrency INTERFACE Threads::Threads)
