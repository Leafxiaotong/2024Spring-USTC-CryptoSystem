#include "AES.hh"
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

AES::AES(int keySize) : keySize(keySize) {
    switch (keySize) {
    case 128:
        numRounds = 10;
        break;
    case 192:
        numRounds = 12;
        break;
    case 256:
        numRounds = 14;
        break;
    }
    for (int i = 0; i < (keySize / 32); ++i) {
        W[i] = (key[4 * i + 0] << 24) | (key[4 * i + 1] << 16) |
               (key[4 * i + 2] << 8) | (key[4 * i + 3]);
    }
    unsigned int tmp, tmp1;
    for (int i = (keySize / 32); i < 4 * (numRounds + 1); ++i) {
        tmp = W[i - 1];
        if (i % (keySize / 32) == 0) {
            tmp1 = tmp;
            tmp = sbox[(tmp1 >> 24) & 0xFF];
            tmp |= sbox[(tmp1 >> 0) & 0xFF] << 8;
            tmp |= sbox[(tmp1 >> 8) & 0xFF] << 16;
            tmp |= (sbox[(tmp1 >> 16) & 0xFF] ^ rcon[i / (keySize / 32) - 1])
                   << 24;
        } else if ((keySize / 32) > 6 && i % (keySize / 32) == 4) {
            tmp1 = tmp;
            tmp = sbox[(tmp1 >> 0) & 0xFF];
            tmp |= sbox[(tmp1 >> 8) & 0xFF] << 8;
            tmp |= sbox[(tmp1 >> 16) & 0xFF] << 16;
            tmp |= sbox[(tmp1 >> 24) & 0xFF] << 24;
        }
        W[i] = W[i - (keySize / 32)] ^ tmp;
    }
    for (int i = 0; i < 4; i++) {
        DW[i] = W[i];
    }
    for (int i = 4; i < 4 * numRounds; i++) {
        DW[i] = TD[sbox[(W[i] >> 24) & 0xFF]];
        tmp = TD[sbox[(W[i] >> 16) & 0xFF]];
        DW[i] ^= rotr32(tmp, 8);
        tmp = TD[sbox[(W[i] >> 8) & 0xFF]];
        DW[i] ^= rotr32(tmp, 16);
        tmp = TD[sbox[(W[i] >> 0) & 0xFF]];
        DW[i] ^= rotr32(tmp, 24);
    }
    for (int i = 0; i < 4; i++) {
        DW[4 * numRounds + i] = W[4 * numRounds + i];
    }
}

std::vector<std::vector<unsigned char>>
AES::Array_to_Matrix(const std::vector<unsigned char> plaintext) {
    std::vector<unsigned char> temp(4);
    std::vector<std::vector<unsigned char>> State_Matrix(4);
    State_Matrix.clear();
    for (int i = 0; i < 4; ++i) {
        temp.clear();
        for (int j = 0; j < 4; ++j) {
            temp.push_back(plaintext[4 * j + i]);
        }
        State_Matrix.push_back(temp);
    }
    return State_Matrix;
}

void AES::setkey(const unsigned char new_key[32]) {
    std::memcpy(key, new_key, keySize / 8);
}

void AES::AddRoundKey(std::vector<std::vector<unsigned char>> &state_matrix,
                      int cnt) {
    for (int col = 0; col < 4; col++) {
        std::array<unsigned char, 4> key8 = Key32toKey8(W[4 * cnt + col]);
        for (int row = 0; row < 4; row++) {
            state_matrix[row][col] ^= key8[row];
        }
    }
}

std::array<unsigned char, 4> AES::Key32toKey8(uint32_t w) {
    std::array<unsigned char, 4> key8{};
    unsigned int mark = 0xff;
    int left_bit;
    for (int i = 0; i < 4; i++) {
        left_bit = (3 - i) * 8;
        key8[i] = ((mark << left_bit) & w) >> left_bit;
    }
    return key8;
}

unsigned char AES::multi_finite_field(unsigned char a, unsigned char b) {
    unsigned char ans = 0, v;
    for (int counter = 0; counter < 8; counter++) {
        if ((b & 0x01) != 0) {
            ans ^= a;
        }
        v = a >> 7;
        a <<= 1;
        if (v != 0) {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    return ans;
}

std::vector<unsigned char>
AES::Matrix_to_Array(std::vector<std::vector<unsigned char>> state_matrix) {
    std::vector<unsigned char> cipher128;
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            cipher128.push_back(state_matrix[row][col]);
        }
    }
    return cipher128;
}

unsigned char AES::SubBytes(unsigned char input) {
    unsigned char pre = 0xf0;
    unsigned char suf = 0x0f;
    unsigned int row = (input & pre) >> 4, col = input & suf;
    return sbox[row * 16UL + col];
}

void AES::ShiftRows(std::vector<std::vector<unsigned char>> &state_matrix) {
    unsigned char temp_row[4];
    for (int i = 1; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            temp_row[j] = state_matrix[i][(j + 4 + i) % 4];
        }
        for (int j = 0; j < 4; j++) {
            state_matrix[i][j] = temp_row[j];
        }
    }
}

void AES::MixColumns(std::vector<std::vector<unsigned char>> &state_matrix) {
    unsigned char ans_mat[4][4];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ans_mat[i][j] = 0;
            for (int k = 0; k < 4; k++) {
                ans_mat[i][j] ^= multi_finite_field(positive_matrix[i][k],
                                                    state_matrix[k][j]);
            }
        }
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state_matrix[i][j] = ans_mat[i][j];
        }
    }
}

std::string AES::Encrypt(const std::string plaintext) {
    int len = plaintext.size();
    int group_cnt = (len + 15) / 16;
    std::vector<unsigned char> ciphertext;
    for (int group = 0; group < group_cnt; group++) {
        std::string plaintext_ = plaintext.substr(group * 16, 16);
        std::vector<unsigned char> plaintext128(plaintext_.begin(),
                                                plaintext_.end());
        std::vector<std::vector<unsigned char>> State_Matrix{};
        State_Matrix = Array_to_Matrix(plaintext128);
        AddRoundKey(State_Matrix, 0);
        for (int i = 1; i <= numRounds; ++i) {
            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    State_Matrix[row][col] = SubBytes(State_Matrix[row][col]);
                }
            }
            ShiftRows(State_Matrix);
            if (i != numRounds) {
                MixColumns(State_Matrix);
            }
            AddRoundKey(State_Matrix, i);
        }
        std::vector<unsigned char> cipher128 = Matrix_to_Array(State_Matrix);
        ciphertext.insert(ciphertext.end(), cipher128.begin(), cipher128.end());
    }
    std::string cipher(ciphertext.begin(), ciphertext.end());
    return cipher;
}

unsigned char AES::Inv_SubBytes(unsigned char input) {
    unsigned char pre = 0xf0;
    unsigned char suf = 0x0f;
    unsigned int row = (input & pre) >> 4, col = input & suf;
    return rsbox[row * 16UL + col];
}

void AES::Inv_ShiftRows(std::vector<std::vector<unsigned char>> &state_matrix) {
    unsigned char temp_row[4];
    for (int i = 1; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            temp_row[(j + 4 + i) % 4] = state_matrix[i][j];
        }
        for (int j = 0; j < 4; j++) {
            state_matrix[i][j] = temp_row[j];
        }
    }
}

void AES::Inv_MixColumns(
    std::vector<std::vector<unsigned char>> &state_matrix) {
    unsigned char ans_mat[4][4];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ans_mat[i][j] = 0;
            for (int k = 0; k < 4; k++) {
                ans_mat[i][j] ^= multi_finite_field(inv_positive_matrix[i][k],
                                                    state_matrix[k][j]);
            }
        }
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state_matrix[i][j] = ans_mat[i][j];
        }
    }
}

std::string AES::Decrypt(const std::string ciphertext) {
    int len = ciphertext.size();
    int group_cnt = (len + 15) / 16;
    std::vector<unsigned char> plaintext;
    for (int group = 0; group < group_cnt; group++) {
        std::string ciphertext_ = ciphertext.substr(group * 16, 16);
        std::vector<unsigned char> ciphertext128(ciphertext_.begin(),
                                                 ciphertext_.end());
        std::vector<std::vector<unsigned char>> State_Matrix{};
        State_Matrix = Array_to_Matrix(ciphertext128);
        AddRoundKey(State_Matrix, numRounds);
        for (int i = numRounds - 1; i >= 0; --i) {
            Inv_ShiftRows(State_Matrix);
            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    State_Matrix[row][col] =
                        Inv_SubBytes(State_Matrix[row][col]);
                }
            }
            AddRoundKey(State_Matrix, i);
            if (i != 0) {
                Inv_MixColumns(State_Matrix);
            }
        }
        std::vector<unsigned char> plain128 = Matrix_to_Array(State_Matrix);
        plaintext.insert(plaintext.end(), plain128.begin(), plain128.end());
    }
    std::string plain(plaintext.begin(), plaintext.end());
    return plain;
}

std::string AES::Tbox_Encrypt(const std::string plaintext) {
    int len = plaintext.size();
    int group_cnt = (len + 15) / 16;
    std::array<unsigned char, 16> cipher128;
    std::vector<unsigned char> ciphertext;
    for (int group = 0; group < group_cnt; group++) {
        std::string plaintext_ = plaintext.substr(group * 16, 16);
        std::vector<unsigned char> plaintext128(plaintext_.begin(),
                                                plaintext_.end());
        uint32_t s[4];
        uint32_t t[4];
        uint32_t tmp;
        for (int i = 0; i < 4; i++) {
            s[i] = (plaintext128[4 * i + 0] << 24) |
                   (plaintext128[4 * i + 1] << 16) |
                   (plaintext128[4 * i + 2] << 8) | (plaintext128[4 * i + 3]);
        }
        s[0] ^= W[0];
        s[1] ^= W[1];
        s[2] ^= W[2];
        s[3] ^= W[3];
        for (int i = 1; i < numRounds; i++) {
            t[0] = TE[(s[0] >> 24) & 0xFF];
            tmp = TE[(s[1] >> 16) & 0xFF];
            t[0] ^= rotr32(tmp, 8);
            tmp = TE[(s[2] >> 8) & 0xFF];
            t[0] ^= rotr32(tmp, 16);
            tmp = TE[(s[3] >> 0) & 0xFF];
            t[0] ^= rotr32(tmp, 24);
            // t1
            t[1] = TE[(s[1] >> 24) & 0xFF];
            tmp = TE[(s[2] >> 16) & 0xFF];
            t[1] ^= rotr32(tmp, 8);
            tmp = TE[(s[3] >> 8) & 0xFF];
            t[1] ^= rotr32(tmp, 16);
            tmp = TE[(s[0] >> 0) & 0xFF];
            t[1] ^= rotr32(tmp, 24);
            // t2
            t[2] = TE[(s[2] >> 24) & 0xFF];
            tmp = TE[(s[3] >> 16) & 0xFF];
            t[2] ^= rotr32(tmp, 8);
            tmp = TE[(s[0] >> 8) & 0xFF];
            t[2] ^= rotr32(tmp, 16);
            tmp = TE[(s[1] >> 0) & 0xFF];
            t[2] ^= rotr32(tmp, 24);
            // t3
            t[3] = TE[(s[3] >> 24) & 0xFF];
            tmp = TE[(s[0] >> 16) & 0xFF];
            t[3] ^= rotr32(tmp, 8);
            tmp = TE[(s[1] >> 8) & 0xFF];
            t[3] ^= rotr32(tmp, 16);
            tmp = TE[(s[2] >> 0) & 0xFF];
            t[3] ^= rotr32(tmp, 24);
            s[0] = t[0] ^ W[4 * i + 0];
            s[1] = t[1] ^ W[4 * i + 1];
            s[2] = t[2] ^ W[4 * i + 2];
            s[3] = t[3] ^ W[4 * i + 3];
        }
        t[0] = sbox[(s[0] >> 24) & 0xFF] << 24;
        t[0] |= sbox[(s[1] >> 16) & 0xFF] << 16;
        t[0] |= sbox[(s[2] >> 8) & 0xFF] << 8;
        t[0] |= sbox[(s[3] >> 0) & 0xFF] << 0;
        t[1] = sbox[(s[1] >> 24) & 0xFF] << 24;
        t[1] |= sbox[(s[2] >> 16) & 0xFF] << 16;
        t[1] |= sbox[(s[3] >> 8) & 0xFF] << 8;
        t[1] |= sbox[(s[0] >> 0) & 0xFF] << 0;
        t[2] = sbox[(s[2] >> 24) & 0xFF] << 24;
        t[2] |= sbox[(s[3] >> 16) & 0xFF] << 16;
        t[2] |= sbox[(s[0] >> 8) & 0xFF] << 8;
        t[2] |= sbox[(s[1] >> 0) & 0xFF] << 0;
        t[3] = sbox[(s[3] >> 24) & 0xFF] << 24;
        t[3] |= sbox[(s[0] >> 16) & 0xFF] << 16;
        t[3] |= sbox[(s[1] >> 8) & 0xFF] << 8;
        t[3] |= sbox[(s[2] >> 0) & 0xFF] << 0;
        s[0] = t[0] ^ W[4 * numRounds + 0];
        s[1] = t[1] ^ W[4 * numRounds + 1];
        s[2] = t[2] ^ W[4 * numRounds + 2];
        s[3] = t[3] ^ W[4 * numRounds + 3];
        for (int i = 0; i < 4; i++) {
            cipher128[4 * i + 0] = (s[i] >> 24) & 0xFF;
            cipher128[4 * i + 1] = (s[i] >> 16) & 0xFF;
            cipher128[4 * i + 2] = (s[i] >> 8) & 0xFF;
            cipher128[4 * i + 3] = (s[i] >> 0) & 0xFF;
        }
        ciphertext.insert(ciphertext.end(), cipher128.begin(), cipher128.end());
    }
    std::string cipher(ciphertext.begin(), ciphertext.end());
    return cipher;
}

std::string AES::Tbox_Decrypt(const std::string ciphertext) {
    int len = ciphertext.size();
    int group_cnt = (len + 15) / 16;
    std::array<unsigned char, 16> plain128;
    std::vector<unsigned char> plaintext;
    for (int group = 0; group < group_cnt; group++) {
        std::string ciphertext_ = ciphertext.substr(group * 16, 16);
        std::vector<unsigned char> ciphertext128(ciphertext_.begin(),
                                                 ciphertext_.end());
        uint32_t s[4];
        uint32_t t[4];
        uint32_t tmp;
        for (int i = 0; i < 4; i++) {
            s[i] = (ciphertext128[4 * i + 0] << 24) |
                   (ciphertext128[4 * i + 1] << 16) |
                   (ciphertext128[4 * i + 2] << 8) | (ciphertext128[4 * i + 3]);
        }
        s[0] ^= DW[4 * numRounds + 0];
        s[1] ^= DW[4 * numRounds + 1];
        s[2] ^= DW[4 * numRounds + 2];
        s[3] ^= DW[4 * numRounds + 3];
        for (int i = numRounds - 1; i > 0; i--) {
            t[0] = TD[(s[0] >> 24) & 0xFF];
            tmp = TD[(s[3] >> 16) & 0xFF];
            t[0] ^= rotr32(tmp, 8);
            tmp = TD[(s[2] >> 8) & 0xFF];
            t[0] ^= rotr32(tmp, 16);
            tmp = TD[(s[1] >> 0) & 0xFF];
            t[0] ^= rotr32(tmp, 24);
            // t1
            t[1] = TD[(s[1] >> 24) & 0xFF];
            tmp = TD[(s[0] >> 16) & 0xFF];
            t[1] ^= rotr32(tmp, 8);
            tmp = TD[(s[3] >> 8) & 0xFF];
            t[1] ^= rotr32(tmp, 16);
            tmp = TD[(s[2] >> 0) & 0xFF];
            t[1] ^= rotr32(tmp, 24);
            // t2
            t[2] = TD[(s[2] >> 24) & 0xFF];
            tmp = TD[(s[1] >> 16) & 0xFF];
            t[2] ^= rotr32(tmp, 8);
            tmp = TD[(s[0] >> 8) & 0xFF];
            t[2] ^= rotr32(tmp, 16);
            tmp = TD[(s[3] >> 0) & 0xFF];
            t[2] ^= rotr32(tmp, 24);
            // t3
            t[3] = TD[(s[3] >> 24) & 0xFF];
            tmp = TD[(s[2] >> 16) & 0xFF];
            t[3] ^= rotr32(tmp, 8);
            tmp = TD[(s[1] >> 8) & 0xFF];
            t[3] ^= rotr32(tmp, 16);
            tmp = TD[(s[0] >> 0) & 0xFF];
            t[3] ^= rotr32(tmp, 24);
            s[0] = t[0] ^ DW[4 * i + 0];
            s[1] = t[1] ^ DW[4 * i + 1];
            s[2] = t[2] ^ DW[4 * i + 2];
            s[3] = t[3] ^ DW[4 * i + 3];
        }
        t[0] = rsbox[(s[0] >> 24) & 0xFF] << 24;
        t[0] |= rsbox[(s[3] >> 16) & 0xFF] << 16;
        t[0] |= rsbox[(s[2] >> 8) & 0xFF] << 8;
        t[0] |= rsbox[(s[1] >> 0) & 0xFF] << 0;
        t[1] = rsbox[(s[1] >> 24) & 0xFF] << 24;
        t[1] |= rsbox[(s[0] >> 16) & 0xFF] << 16;
        t[1] |= rsbox[(s[3] >> 8) & 0xFF] << 8;
        t[1] |= rsbox[(s[2] >> 0) & 0xFF] << 0;
        t[2] = rsbox[(s[2] >> 24) & 0xFF] << 24;
        t[2] |= rsbox[(s[1] >> 16) & 0xFF] << 16;
        t[2] |= rsbox[(s[0] >> 8) & 0xFF] << 8;
        t[2] |= rsbox[(s[3] >> 0) & 0xFF] << 0;
        t[3] = rsbox[(s[3] >> 24) & 0xFF] << 24;
        t[3] |= rsbox[(s[2] >> 16) & 0xFF] << 16;
        t[3] |= rsbox[(s[1] >> 8) & 0xFF] << 8;
        t[3] |= rsbox[(s[0] >> 0) & 0xFF] << 0;
        s[0] = t[0] ^ DW[0];
        s[1] = t[1] ^ DW[1];
        s[2] = t[2] ^ DW[2];
        s[3] = t[3] ^ DW[3];
        for (int i = 0; i < 4; i++) {
            plain128[4 * i + 0] = (s[i] >> 24) & 0xFF;
            plain128[4 * i + 1] = (s[i] >> 16) & 0xFF;
            plain128[4 * i + 2] = (s[i] >> 8) & 0xFF;
            plain128[4 * i + 3] = (s[i] >> 0) & 0xFF;
        }
        plaintext.insert(plaintext.end(), plain128.begin(), plain128.end());
    }
    std::string plain(plaintext.begin(), plaintext.end());
    return plain;
}

std::string AES::AESNI_Encrypt(std::string plain) {
    aes128_load_key((int8_t *)key);
    int len = plain.size();
    int group_cnt = (len + 15) / 16;
    std::string cipher;
    for (int group = 0; group < group_cnt; group++) {
        std::string plaintext_ = plain.substr(group * 16, 16);
        const unsigned char *plaintext =
            reinterpret_cast<const unsigned char *>(plaintext_.c_str());
        unsigned char ciphertext[16];
        aes128_enc((int8_t *)plaintext, (int8_t *)ciphertext);
        std::string cipher128(reinterpret_cast<const char *>(ciphertext), 16);
        cipher += cipher128;
    }
    return cipher;
}

std::string AES::AESNI_Decrypt(std::string cipher) {
    int len = cipher.size();
    int group_cnt = (len + 15) / 16;
    std::string plain;
    for (int group = 0; group < group_cnt; group++) {
        std::string ciphertext_ = cipher.substr(group * 16, 16);
        const unsigned char *ciphertext =
            reinterpret_cast<const unsigned char *>(ciphertext_.c_str());
        unsigned char plaintext[16];
        aes128_dec((int8_t *)ciphertext, (int8_t *)plaintext);
        std::string plain128(reinterpret_cast<const char *>(plaintext), 16);
        plain += plain128;
    }
    return plain;
}