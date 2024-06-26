#include "AES.hh"

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened) {
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

// public API
void aes128_load_key(int8_t *enc_key) {
    key_schedule[0] = _mm_loadu_si128((const __m128i *)enc_key);
    key_schedule[1] = AES_128_key_exp(key_schedule[0], 0x01);
    key_schedule[2] = AES_128_key_exp(key_schedule[1], 0x02);
    key_schedule[3] = AES_128_key_exp(key_schedule[2], 0x04);
    key_schedule[4] = AES_128_key_exp(key_schedule[3], 0x08);
    key_schedule[5] = AES_128_key_exp(key_schedule[4], 0x10);
    key_schedule[6] = AES_128_key_exp(key_schedule[5], 0x20);
    key_schedule[7] = AES_128_key_exp(key_schedule[6], 0x40);
    key_schedule[8] = AES_128_key_exp(key_schedule[7], 0x80);
    key_schedule[9] = AES_128_key_exp(key_schedule[8], 0x1B);
    key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);

    // generate decryption keys in reverse order.
    // k[10] is shared by last encryption and first decryption rounds
    // k[0] is shared by first encryption round and last decryption round (and
    // is the original user key) For some implementation reasons, decryption key
    // schedule is NOT the encryption key schedule in reverse order
    key_schedule[11] = _mm_aesimc_si128(key_schedule[9]);
    key_schedule[12] = _mm_aesimc_si128(key_schedule[8]);
    key_schedule[13] = _mm_aesimc_si128(key_schedule[7]);
    key_schedule[14] = _mm_aesimc_si128(key_schedule[6]);
    key_schedule[15] = _mm_aesimc_si128(key_schedule[5]);
    key_schedule[16] = _mm_aesimc_si128(key_schedule[4]);
    key_schedule[17] = _mm_aesimc_si128(key_schedule[3]);
    key_schedule[18] = _mm_aesimc_si128(key_schedule[2]);
    key_schedule[19] = _mm_aesimc_si128(key_schedule[1]);
}

void aes128_enc(int8_t *plainText, int8_t *cipherText) {
    __m128i m = _mm_loadu_si128((__m128i *)plainText);

    DO_ENC_BLOCK(m, key_schedule);

    _mm_storeu_si128((__m128i *)cipherText, m);
}

void aes128_dec(int8_t *cipherText, int8_t *plainText) {
    __m128i m = _mm_loadu_si128((__m128i *)cipherText);

    DO_DEC_BLOCK(m, key_schedule);

    _mm_storeu_si128((__m128i *)plainText, m);
}