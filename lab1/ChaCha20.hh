#include <array>
#include <cstdint>
#include <functional>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <vector>
#include <bitset>
#include <cstdint>
#include <sstream>
class ChaCha20 {
  private:
    int block_size = 64;
    int key_size = 32;
    std::array<uint32_t, 8> key;
    std::array<uint32_t, 3> nonce;
    std::array<uint32_t, 16> Matrix;

  public:
    ChaCha20(std::array<uint32_t, 8> key, std::array<uint32_t, 3> nonce);
    std::string xor_bytes(const std::string &data_1, const std::string &data_2);
    uint32_t circular_left(uint32_t num, size_t i);
    void rounds(std::array<uint32_t, 16> &state);
    std::string encrypt(std::string plaintext, uint32_t counter);
    std::string decrypt(std::string ciphertext, uint32_t counter);
    std::array<uint32_t, 4> quarterround(uint32_t a, uint32_t b, uint32_t c,
                                         uint32_t d);
    std::string operation(bool oprate, std::string input, uint32_t count_start);
};