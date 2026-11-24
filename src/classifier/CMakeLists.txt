add_library(dpi_classifier classifier.cpp)
add_library(dpi::classifier ALIAS dpi_classifier)
target_include_directories(dpi_classifier PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(dpi_classifier PUBLIC dpi_common PRIVATE dpi_warnings)
