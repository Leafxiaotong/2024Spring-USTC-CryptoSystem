#include "ChaCha20.hh"

ChaCha20::ChaCha20(std::array<uint32_t, 8> key, std::array<uint32_t, 3> nonce)
    : key(key), nonce(nonce),
      Matrix({0x61707865, 0x3320646E, 0x79622D32, 0x6B206574, key[0], key[1],
              key[2], key[3], key[4], key[5], key[6], key[7], 0, nonce[0],
              nonce[1], nonce[2]}) {}

std::string ChaCha20::xor_bytes(const std::string &data_1,
                                const std::string &data_2) {
    size_t min_length = std::min(data_1.length(), data_2.length());
    std::string result;
    for (size_t i = 0; i < min_length; ++i) {
        // XOR each byte of data_1 and data_2
        result += data_1[i] ^ data_2[i];
    }
    return result;
}

uint32_t ChaCha20::circular_left(uint32_t num, size_t i) {
    std::string binary_repr = std::bitset<32>(num).to_string();
    binary_repr = binary_repr.substr(i, key_size);
    return std::bitset<32>(binary_repr).to_ulong();
}

std::array<uint32_t, 4> ChaCha20::quarterround(uint32_t a, uint32_t b,
                                               uint32_t c, uint32_t d) {
    std::array<uint32_t, 4> result;
    a += b;
    d ^= a;
    d = circular_left(d, 16);
    c += d;
    b ^= c;
    b = circular_left(b, 12);
    a += b;
    d ^= a;
    d = circular_left(d, 8);
    c += d;
    b ^= c;
    b = circular_left(b, 7);
    result = {a, b, c, d};
    return result;
}

void ChaCha20::rounds(std::array<uint32_t, 16> &state) {
    std::array<std::array<uint32_t, 4>, 8> steps;
    steps[0] = {0, 4, 8, 12};
    steps[1] = {1, 5, 9, 13};
    steps[2] = {2, 6, 10, 14};
    steps[3] = {3, 7, 11, 15};
    steps[4] = {0, 5, 10, 15};
    steps[5] = {1, 6, 11, 12};
    steps[6] = {2, 7, 8, 13};
    steps[7] = {3, 4, 9, 14};
    for (int i = 0; i < 10; ++i) {
        for (const auto &round : steps) {
            std::array<uint32_t, 4> update =
                quarterround(state[round[0]], state[round[1]], state[round[2]],
                             state[round[3]]);
            state[round[0]] = update[0];
            state[round[1]] = update[1];
            state[round[2]] = update[2];
            state[round[3]] = update[3];
        }
    }
}

std::string ChaCha20::encrypt(std::string plaintext, uint32_t counter) {
    Matrix[12] = counter;
    std::array<uint32_t, 16> state = Matrix;
    rounds(state);
    std::array<uint32_t, 16> final;
    for (int i; i < final.size(); ++i) {
        final[i] = state[i] + Matrix[i];
    }
    std::stringstream ss;
    for (const auto &val : final) {
        ss.write(reinterpret_cast<const char *>(&val), sizeof(uint32_t));
    }
    std::string serial_out = ss.str();
    return xor_bytes(plaintext, serial_out);
}

std::string ChaCha20::decrypt(std::string ciphertext, uint32_t counter) {
    return encrypt(ciphertext, counter);
}

std::string ChaCha20::operation(bool oprate, std::string input,
                                uint32_t count_start) {
    int len = input.size();
    int group_cnt = (len + 63) / 64;
    std::string output;
    if (oprate == 0) {
        for (int group = 0; group < group_cnt; group++) {
            std::string input_ = input.substr(group * 64, 64);
            std::string output_ = encrypt(input_, group_cnt + count_start);
            output += output_;
        }
    } else {
        for (int group = 0; group < group_cnt; group++) {
            std::string input_ = input.substr(group * 64, 64);
            std::string output_ = decrypt(input_, group_cnt + count_start);
            output += output_;
        }
    }
    return output;
}