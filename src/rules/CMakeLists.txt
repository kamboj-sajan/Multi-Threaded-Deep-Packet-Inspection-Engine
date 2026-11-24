add_library(dpi_rules rule_set.cpp)
add_library(dpi::rules ALIAS dpi_rules)
target_include_directories(dpi_rules PUBLIC ${PROJECT_SOURCE_DIR}/include)
# Domain rules are validated with the same host-name rules as SNI.
target_link_libraries(dpi_rules PUBLIC dpi_common PRIVATE dpi_inspect dpi_warnings)
