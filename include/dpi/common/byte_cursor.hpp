#pragma once

// Sequential, bounds-checked reader over an untrusted byte buffer.
//
// Every read checks the remaining length first and fails (returns false)
// instead of reading past the end. Parsers for variable-length protocol
// structures (TLS, HTTP) are written against this so that "check every
// length against the remaining bytes" is enforced in one place.

#include <cstddef>
#include <cstdint>
#include <optional>

#include "dpi/common/bytes.hpp"

namespace dpi {

class ByteCursor {
 public:
  explicit ByteCursor(ByteView data) noexcept : data_(data) {}

  std::size_t remaining() const noexcept { return data_.size() - pos_; }
  bool empty() const noexcept { return remaining() == 0; }

  bool read_u8(std::uint8_t& out) noexcept {
    if (remaining() < 1) {
      return false;
    }
    out = load_u8(data_, pos_);
    pos_ += 1;
    return true;
  }

  bool read_u16(std::uint16_t& out) noexcept {
    if (remaining() < 2) {
      return false;
    }
    out = load_be16(data_, pos_);
    pos_ += 2;
    return true;
  }

  // 24-bit big-endian length, as used by TLS handshake headers.
  bool read_u24(std::uint32_t& out) noexcept {
    if (remaining() < 3) {
      return false;
    }
    out = (std::uint32_t{load_u8(data_, pos_)} << 16) | load_be16(data_, pos_ + 1);
    pos_ += 3;
    return true;
  }

  bool skip(std::size_t n) noexcept {
    if (remaining() < n) {
      return false;
    }
    pos_ += n;
    return true;
  }

  // Splits off the next `n` bytes as their own cursor, so a nested
  // structure can never read past its declared length.
  std::optional<ByteCursor> sub(std::size_t n) noexcept {
    if (remaining() < n) {
      return std::nullopt;
    }
    ByteCursor child(data_.subspan(pos_, n));
    pos_ += n;
    return child;
  }

  ByteView rest() const noexcept { return data_.subspan(pos_); }

 private:
  ByteView data_;
  std::size_t pos_ = 0;
};

}  // namespace dpi
