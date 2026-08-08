#ifndef BIP39_SECURE_MEM_SECURE_BUFFER_HPP_
#define BIP39_SECURE_MEM_SECURE_BUFFER_HPP_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <stdexcept>
#include <utility>

#include <sodium.h>

namespace secure_mem {

// RAII wrapper guaranteeing zeroization of sensitive memory.
//
// - Memory is mlock()ed where the OS allows it (best-effort: mlock failures do
//   not compromise the zeroization guarantee, which is unconditional).
// - Memory is sodium_memzero()ed before being released, on every path,
//   including exception paths and scope exit.
// - Move-only: copies are impossible by construction, preventing accidental
//   duplication of secret material.
template <typename T>
class buffer {
 public:
  using value_type = T;

  buffer() = default;
  explicit buffer(std::size_t n) { resize(n); }

  buffer(buffer&& other) noexcept : ptr_(other.ptr_), size_(other.size_) {
    other.ptr_ = nullptr;
    other.size_ = 0;
  }

  buffer& operator=(buffer&& other) noexcept {
    if (this != &other) {
      release();
      ptr_ = other.ptr_;
      size_ = other.size_;
      other.ptr_ = nullptr;
      other.size_ = 0;
    }
    return *this;
  }

  buffer(const buffer&) = delete;
  buffer& operator=(const buffer&) = delete;

  ~buffer() { release(); }

  // Reallocate to `n` elements. If `preserve` is false the new region is
  // zero-initialized; if true the first min(n, old) bytes are carried over.
  void resize(std::size_t n, bool preserve = false) {
    if (n == size_) return;
    T* np = (n != 0) ? static_cast<T*>(::operator new[](n * sizeof(T))) : nullptr;
    if (n != 0 && np == nullptr) throw std::bad_alloc();
    if (np != nullptr) {
      if (preserve && ptr_ != nullptr) {
        const std::size_t keep = (n < size_) ? n : size_;
        // Zero the whole new region first so the tail beyond the copied bytes
        // never carries uninitialized heap data, then copy the preserved data.
        std::memset(np, 0, n * sizeof(T));
        std::memcpy(np, ptr_, keep * sizeof(T));
      } else {
        std::memset(np, 0, n * sizeof(T));
      }
      // mlock is best-effort; failing to lock does not weaken zeroization.
      (void)sodium_mlock(np, n * sizeof(T));
    }
    release();
    ptr_ = np;
    size_ = n;
  }

  // Zero the contents in place without releasing the allocation.
  void zero() noexcept {
    if (ptr_ != nullptr && size_ != 0) sodium_memzero(ptr_, size_ * sizeof(T));
  }

  // Zero and release the allocation.
  void release_and_zero() noexcept { release(); }

  T* data() noexcept { return ptr_; }
  const T* data() const noexcept { return ptr_; }
  std::size_t size() const noexcept { return size_; }
  bool empty() const noexcept { return size_ == 0; }

 private:
  void release() noexcept {
    if (ptr_ != nullptr) {
      sodium_memzero(ptr_, size_ * sizeof(T));
      ::operator delete[](ptr_);
      ptr_ = nullptr;
      size_ = 0;
    }
  }

  T* ptr_ = nullptr;
  std::size_t size_ = 0;
};

using byte_buffer = buffer<std::uint8_t>;

// Null-terminated mutable string backed by mlock'ed memory. Used to hold
// user-supplied entropy input and generated mnemonics.
class secure_string {
 public:
  secure_string() { buf_.resize(1); }
  ~secure_string() { wipe(); }

  secure_string(secure_string&& other) noexcept
      : buf_(std::move(other.buf_)), len_(other.len_) {
    other.reset_to_empty();
  }

  secure_string& operator=(secure_string&& other) noexcept {
    if (this != &other) {
      buf_ = std::move(other.buf_);
      len_ = other.len_;
      other.reset_to_empty();
    }
    return *this;
  }

  secure_string(const secure_string&) = delete;
  secure_string& operator=(const secure_string&) = delete;

  void assign(const char* s, std::size_t n) {
    ensure_capacity(n);
    std::memcpy(buf_.data(), s, n);
    buf_.data()[n] = '\0';
    len_ = n;
  }

  void assign(const char* s) { assign(s, std::strlen(s)); }

  void append(const char* s, std::size_t n) {
    const std::size_t old = len_;
    ensure_capacity(old + n);
    std::memcpy(buf_.data() + old, s, n);
    buf_.data()[old + n] = '\0';
    len_ = old + n;
  }

  void clear() noexcept { if (buf_.data() != nullptr) buf_.data()[0] = '\0'; len_ = 0; }

  void wipe() noexcept { buf_.zero(); len_ = 0; }

  char* data() noexcept { return buf_.data(); }
  const char* data() const noexcept { return buf_.data(); }
  const char* c_str() const noexcept { return buf_.data(); }
  std::size_t size() const noexcept { return len_; }
  bool empty() const noexcept { return len_ == 0; }

 private:
  void ensure_capacity(std::size_t need) {
    if (need + 1 <= buf_.size()) return;
    std::size_t cap = (buf_.size() != 0) ? buf_.size() * 2 : 64;
    while (cap < need + 1) cap *= 2;
    buf_.resize(cap, /*preserve=*/true);
  }

  void reset_to_empty() noexcept {
    buf_.resize(1, /*preserve=*/false);
    len_ = 0;
  }

  buffer<char> buf_;
  std::size_t len_ = 0;
};

}  // namespace secure_mem

#endif  // BIP39_SECURE_MEM_SECURE_BUFFER_HPP_
