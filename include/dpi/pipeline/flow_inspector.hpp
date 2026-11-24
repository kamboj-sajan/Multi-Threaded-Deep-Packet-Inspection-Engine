#pragma once

#include <cstddef>
#include <cstdint>

#include "dpi/classifier/classifier.hpp"
#include "dpi/flow/flow_entry.hpp"
#include "dpi/parser/parsed_packet.hpp"

namespace dpi {

struct InspectionConfig {
  // Payload-carrying packets (either direction) to look at before giving
  // up. A ClientHello or HTTP request is the client's first payload, so a
  // handful is plenty; after that the flow is on the fast path.
  std::uint8_t max_payload_packets = 4;
  // Cap on bytes buffered to reassemble a split ClientHello / request.
  std::size_t max_reassembly_bytes = 16 * 1024;
};

// Decides what application a flow is, from the first few payload packets.
// Stateless apart from the FlowEntry it is given, so one instance per FP.
//
// Classification order for TCP: TLS ClientHello SNI, then HTTP/1.x Host,
// then the server port. UDP and other protocols use the port only
// (QUIC and DNS payloads are not inspected).
class FlowInspector {
 public:
  explicit FlowInspector(const Classifier& classifier, InspectionConfig config = {})
      : classifier_(classifier), config_(config) {}

  // Gives a brand-new flow its port-based default app. Non-TCP flows are
  // final at this point.
  void on_new_flow(FlowEntry& flow, const ParsedPacket& first) const;

  // Feeds one packet of the flow. Does nothing once inspection is done.
  void inspect(FlowEntry& flow, const ParsedPacket& parsed, ByteView frame, bool from_client) const;

 private:
  enum class Outcome { Classified, NeedMoreBytes, NotRecognised };

  Outcome classify_client_bytes(FlowEntry& flow, ByteView data) const;
  void buffer_for_reassembly(FlowEntry& flow, const ParsedPacket& parsed, ByteView payload) const;
  static void finish(FlowEntry& flow);

  const Classifier& classifier_;
  InspectionConfig config_;
};

}  // namespace dpi
