#include "dpi/flow/tcp_tracker.hpp"

#include "dpi/parser/parsed_packet.hpp"

namespace dpi {

const char* to_string(TcpState state) noexcept {
  switch (state) {
    case TcpState::None: return "none";
    case TcpState::SynSent: return "syn_sent";
    case TcpState::SynReceived: return "syn_received";
    case TcpState::Established: return "established";
    case TcpState::Closing: return "closing";
    case TcpState::Closed: return "closed";
    case TcpState::Reset: return "reset";
  }
  return "unknown";
}

void TcpTracker::on_packet(std::uint8_t flags, bool from_client) noexcept {
  const bool syn = (flags & tcpflag::kSyn) != 0;
  const bool ack = (flags & tcpflag::kAck) != 0;
  const bool fin = (flags & tcpflag::kFin) != 0;

  if (flags & tcpflag::kRst) {
    state_ = TcpState::Reset;
    return;
  }
  if (is_terminal()) {
    return;  // Whether a new SYN starts a new flow is the caller's decision.
  }

  switch (state_) {
    case TcpState::None:
      if (syn && !ack) {
        state_ = TcpState::SynSent;
      } else if (syn && ack) {
        state_ = TcpState::SynReceived;  // We missed the client's SYN.
      } else {
        state_ = TcpState::Established;  // Capture started mid-connection.
      }
      break;
    case TcpState::SynSent:
      if (syn && ack && !from_client) {
        state_ = TcpState::SynReceived;
      }
      break;
    case TcpState::SynReceived:
      if (ack && !syn && from_client) {
        state_ = TcpState::Established;
      }
      break;
    default:
      break;
  }

  if (fin) {
    (from_client ? fin_from_client_ : fin_from_server_) = true;
    state_ = fin_from_client_ && fin_from_server_ ? TcpState::Closed : TcpState::Closing;
  }
}

}  // namespace dpi
