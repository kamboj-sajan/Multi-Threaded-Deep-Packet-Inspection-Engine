# Option parsing is a library so it can be tested without running main().
add_library(dpi_cli cli.cpp)
add_library(dpi::cli ALIAS dpi_cli)
target_include_directories(dpi_cli PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(dpi_cli PRIVATE dpi_warnings)

add_executable(dpi_engine main.cpp)
target_link_libraries(dpi_engine PRIVATE dpi_cli dpi_pipeline dpi_rules dpi_warnings Threads::Threads)
