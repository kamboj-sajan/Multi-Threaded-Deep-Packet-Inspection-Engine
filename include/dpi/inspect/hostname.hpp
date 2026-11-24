#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace dpi {

// Validates and canonicalises a hostname taken from untrusted traffic
// (TLS SNI or HTTP Host): lower-cased, one trailing dot removed, 1-253
// characters of letters, digits, '-', '_' and '.', no leading dot or empty
// label. Returns nullopt if it is not a plausible hostname, so garbage never
// reaches the classifier, rule matching or the report.
std::optional<std::string> canonical_hostname(std::string_view raw);

}  // namespace dpi
