#ifndef BIP39_ENTROPY_ENTROPY_ESTIMATOR_HPP_
#define BIP39_ENTROPY_ENTROPY_ESTIMATOR_HPP_

#include <cstddef>

namespace entropy {

// Heuristic estimate (in bits) of the additional entropy contributed by the
// user's free-text input. This is a Shannon-based *estimate*, NOT a
// cryptographic guarantee. The only guaranteed floor is the OS CSPRNG entropy.
// Returns 0.0 for empty input.
double estimate_user_entropy(const char* input, std::size_t len);

// Coarse security level based on the guaranteed OS entropy bits.
// Because the OS floor is always >= 128 bits, this is effectively always High.
enum class security_level { Low, Medium, High };

security_level classify(std::size_t guaranteed_bits);

const char* to_string(security_level level);

}  // namespace entropy

#endif  // BIP39_ENTROPY_ENTROPY_ESTIMATOR_HPP_
