#include "AES.hh"
#include "ChaCha20.hh"
#include <array>
#include <fstream>
#include <sstream>
#include <ctime>
using namespace std;
clock_t start_t, end_t;

/*g++ ./AES.cpp ./AES-NI.cpp ./main.cpp ./ChaCha20.cc -o test -g -O0 -msse2
 * -march=native -maes*/
int main() {
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    AES aes128(256);
    aes128.setkey(key);
    vector<unsigned char> raw_cipher;
    ifstream input("./input");
    stringstream buffer;
    buffer << input.rdbuf();
    input.close();
    string plain = buffer.str();
    start_t = clock();
    string cipher = aes128.Encrypt(plain);
    string decrypted_cipher = aes128.Decrypt(cipher);
    end_t = clock();
    cout << "The AES running time is "
         << (double)(end_t - start_t) / CLOCKS_PER_SEC << " s" << endl;
    ofstream output_AES("./output_AES");
    output_AES << decrypted_cipher;
    output_AES.close();
    cout << "---------------------------------------------------------" << endl;
    int init_count = 0;
    array<uint32_t, 8> convertedKey;
    for (size_t i = 0; i < 8; ++i) {
        convertedKey[i] = (static_cast<uint32_t>(key[i * 4]) << 24) |
                          (static_cast<uint32_t>(key[i * 4 + 1]) << 16) |
                          (static_cast<uint32_t>(key[i * 4 + 2]) << 8) |
                          static_cast<uint32_t>(key[i * 4 + 3]);
    }
    array<uint32_t, 3> nonce = {0, 0, 0};
    ChaCha20 chacha(convertedKey, nonce);
    cipher = chacha.operation(false, plain, init_count);
    decrypted_cipher = chacha.operation(true, cipher, init_count);
    end_t = clock();
    cout << "The ChaCha20 running time is "
         << (double)(end_t - start_t) / CLOCKS_PER_SEC << " s" << endl;
    ofstream output_chacha20("./output_chacha20");
    output_chacha20 << decrypted_cipher;
    output_chacha20.close();
}