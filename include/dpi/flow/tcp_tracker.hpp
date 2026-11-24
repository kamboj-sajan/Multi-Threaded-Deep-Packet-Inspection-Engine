#pragma once

#include <cstdint>

namespace dpi {

// Coarse TCP connection state, as observed passively from both directions.
// This is deliberately simpler than the RFC 9293 state machine: a passive
// observer only needs to know whether a connection is opening, open or
// closed, not each endpoint's exact state.
enum class TcpState : std::uint8_t {
  None,         // Not TCP, or no packet seen yet.
  SynSent,      // Client SYN seen.
  SynReceived,  // Server SYN-ACK seen.
  Established,  // Handshake completed, or connection joined mid-stream.
  Closing,      // FIN seen from one side.
  Closed,       // FIN seen from both sides.
  Reset,        // RST seen.
};

const char* to_string(TcpState state) noexcept;

class TcpTracker {
 public:
  void on_packet(std::uint8_t tcp_flags, bool from_client) noexcept;

  TcpState state() const noexcept { return state_; }
  bool is_terminal() const noexcept {
    return state_ == TcpState::Closed || state_ == TcpState::Reset;
  }

 private:
  TcpState state_ = TcpState::None;
  bool fin_from_client_ = false;
  bool fin_from_server_ = false;
};

}  // namespace dpi
