# One library per layer so each can be unit-tested in isolation.
add_subdirectory(common)
add_subdirectory(pcap_io)
add_subdirectory(parser)
add_subdirectory(flow)
add_subdirectory(inspect)
add_subdirectory(concurrency)
add_subdirectory(pipeline)
add_subdirectory(app)
