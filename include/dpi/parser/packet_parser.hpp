#pragma once

#include <cstdint>
#include <optional>

#include "dpi/common/bytes.hpp"
#include "dpi/parser/parsed_packet.hpp"

namespace dpi {

// Fully decodes Ethernet II (with at most one 802.1Q tag), IPv4 and
// TCP/UDP from an untrusted frame.
//
// `wire_len` is the packet's original length on the wire. When it exceeds
// frame.size() the capture was truncated by snaplen; a packet whose headers
// are complete is then still accepted with payload_truncated set. When the
// frame is complete, lengths that point past its end are malformed.
//
// Never reads outside `frame`. On any status other than Ok, `out` holds
// unspecified partial results.
ParseStatus parse_packet(ByteView frame, std::uint32_t wire_len, ParsedPacket& out);

// Convenience overload for a frame captured in full.
inline ParseStatus parse_packet(ByteView frame, ParsedPacket& out) {
  return parse_packet(frame, static_cast<std::uint32_t>(frame.size()), out);
}

// Cheap addressing extraction for the reader thread, which only needs
// enough to pick a load balancer. It skips most validation; the load
// balancer runs parse_packet afterwards. For every packet parse_packet
// accepts, peek_tuple returns the same tuple as ParsedPacket::tuple() (a
// unit test enforces this), which is what keeps flow affinity consistent.
// Returns nullopt for non-IPv4 or unreadable frames.
std::optional<PacketTuple> peek_tuple(ByteView frame) noexcept;

}  // namespace dpi
