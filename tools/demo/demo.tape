# Terminal demo shown at the top of the README (docs/demo.gif).
#
# Re-record from the repository root after a release build:
#   cmake --preset release && cmake --build --preset release
#   vhs tools/demo/demo.tape
#
# Requires vhs (https://github.com/charmbracelet/vhs) and tcpdump.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1400
Set Height 820
Set Padding 24
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 25ms

# Setup, not recorded: put the release binaries on PATH and use a short prompt.
Hide
Type `export PATH="$PWD/build/release/src/app:$PATH" PS1='$ '` Enter
Type "rm -f out.pcap && clear" Enter
Sleep 500ms
Show

# Scene 1: rules in, per-flow verdicts out.
Type "# Four blocking rules: an IP, a domain wildcard, an app and a port" Enter
Type "grep '^block' rules/example_rules.txt" Sleep 300ms Enter
Sleep 1.5s
Type "dpi_engine tests/data/mixed.pcap out.pcap --rules rules/example_rules.txt | head -27" Sleep 300ms Enter
Sleep 6s

# Scene 2: classification from TLS SNI / HTTP Host.
Hide
Type "clear" Enter
Show
Type "# Flows classified from the TLS ClientHello SNI and the HTTP Host header" Enter
Type "dpi_engine tests/data/mixed.pcap out.pcap --rules rules/example_rules.txt | tail -28" Sleep 300ms Enter
Sleep 6s

# Scene 3: the multithreaded pipeline and its load distribution.
Hide
Type "clear" Enter
Show
Type "# 1000 flows through 4 load balancers x 4 fast-path threads each" Enter
Type "dpi_engine tests/data/many_flows.pcap out.pcap --lbs 4 --fps-per-lb 4 | grep -A22 Threads" Sleep 300ms Enter
Sleep 4s
Type "# The output is a normal PCAP" Enter
Type "tcpdump -nn -r out.pcap 'tcp port 443' 2>/dev/null | head -3" Sleep 300ms Enter
Sleep 4s

# Scene 4: the test suite.
Hide
Type "clear" Enter
Show
Type "# 222 unit, integration and determinism tests" Enter
Type "ctest --preset release -j8 | tail -3" Sleep 300ms Enter
Sleep 4s

Hide
Type "rm -f out.pcap" Enter
