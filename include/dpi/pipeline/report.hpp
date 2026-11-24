#pragma once

#include <string>

#include "dpi/pipeline/stats.hpp"

namespace dpi {

inline constexpr std::size_t kTopSniCount = 10;

// Human-readable summary for the terminal.
std::string format_text_report(const RunStats& stats);

// Machine-readable summary (--report report.json). Hand-written to keep the
// project free of third-party dependencies.
std::string format_json_report(const RunStats& stats);

// Escapes a string for inclusion in a JSON document (without quotes).
std::string json_escape(const std::string& s);

}  // namespace dpi
