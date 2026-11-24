dpi_add_test(test_integration SOURCES test_integration.cpp test_determinism.cpp test_classification.cpp test_blocking.cpp
  LIBS dpi::pipeline dpi::test_support)

# CLI-level checks: the real executable, its exit codes, and an output file
# that an independent reader (tcpdump) accepts.
add_test(NAME cli.usage_error COMMAND dpi_engine)
set_tests_properties(cli.usage_error PROPERTIES WILL_FAIL TRUE)
add_test(NAME cli.missing_input COMMAND dpi_engine /nonexistent/in.pcap /tmp/dpi_unused.pcap)
set_tests_properties(cli.missing_input PROPERTIES WILL_FAIL TRUE)
add_test(NAME cli.invalid_rules_file
  COMMAND dpi_engine ${PROJECT_SOURCE_DIR}/tests/data/mixed.pcap /tmp/dpi_unused.pcap
          --rules ${CMAKE_CURRENT_SOURCE_DIR}/bad_rules.txt)
set_tests_properties(cli.invalid_rules_file PROPERTIES WILL_FAIL TRUE)

find_program(TCPDUMP_EXECUTABLE tcpdump)
if(TCPDUMP_EXECUTABLE)
  add_test(NAME cli.tcpdump_reads_output.mixed
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/cli_tcpdump_check.sh
            $<TARGET_FILE:dpi_engine> ${TCPDUMP_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/tests/data/mixed.pcap 244)
  add_test(NAME cli.tcpdump_reads_output.mixed_4x4
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/cli_tcpdump_check.sh
            $<TARGET_FILE:dpi_engine> ${TCPDUMP_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/tests/data/mixed.pcap 244 --lbs 4 --fps-per-lb 4)
  add_test(NAME cli.tcpdump_reads_output.mixed_sequential
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/cli_tcpdump_check.sh
            $<TARGET_FILE:dpi_engine> ${TCPDUMP_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/tests/data/mixed.pcap 244 --sequential)
  # 254 records - 10 malformed - 59 dropped by the example rules.
  add_test(NAME cli.tcpdump_reads_output.mixed_with_rules
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/cli_tcpdump_check.sh
            $<TARGET_FILE:dpi_engine> ${TCPDUMP_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/tests/data/mixed.pcap 185
            --rules ${PROJECT_SOURCE_DIR}/rules/example_rules.txt --lbs 3 --fps-per-lb 2)
else()
  message(STATUS "tcpdump not found: skipping the tcpdump output check")
endif()
