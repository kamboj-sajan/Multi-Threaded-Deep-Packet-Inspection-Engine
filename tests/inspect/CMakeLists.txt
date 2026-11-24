dpi_add_test(test_inspect
  SOURCES test_tls_sni.cpp
  LIBS dpi::inspect dpi::test_support)
target_include_directories(test_inspect PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
