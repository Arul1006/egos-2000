#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define MASK 0xFFFF

static inline uint16_t rotr(uint16_t x, uint8_t n) { return (x >> n) | (x << (16 - n)); }
static inline uint16_t shr(uint16_t x, uint8_t n) { return x >> n; }
static inline uint16_t SIGMA0(uint16_t x) { return rotr(x, 1) ^ rotr(x, 6) ^ rotr(x, 11); }
static inline uint16_t SIGMA1(uint16_t x) { return rotr(x, 3) ^ rotr(x, 5) ^ rotr(x, 12); }
static inline uint16_t sigma0(uint16_t x) { return rotr(x, 3) ^ rotr(x, 7) ^ shr(x, 1); }
static inline uint16_t sigma1(uint16_t x) { return rotr(x, 8) ^ rotr(x, 9) ^ shr(x, 5); }

static inline uint16_t Ch(uint16_t x, uint16_t y, uint16_t z) { return (x & y) ^ ((~x) & z); }
static inline uint16_t Maj(uint16_t x, uint16_t y, uint16_t z) { return (x & y) ^ (x & z) ^ (y & z); }

static const uint16_t K[32] = {
    0x428a,0x7137,0xb5c0,0xe9b5,0x3956,0x59f1,0x923f,0xab1c,
    0xd807,0x1283,0x2431,0x550c,0x72be,0x80de,0x9bdc,0xc19b,
    0xe49b,0xefbe,0x0fc1,0x240c,0x2de9,0x4a74,0x5cb0,0x76f9,
    0x983e,0xa831,0xb003,0xbf59,0xc6e0,0xd5a7,0x06ca,0x1429
};

static const uint16_t IV[8] = { 0x6a09, 0xbb67, 0x3c6e, 0xa54f, 0x510e, 0x9b05, 0x1f83, 0x5be0 };

static inline void compress(uint16_t* H, const uint16_t* block_words) {
    uint16_t W[32];
    for (int i = 0; i < 8; i++) W[i] = block_words[i];
    
    for (int t = 8; t < 32; t++) {
        W[t] = (sigma1(W[t - 2]) + W[t - 4] + sigma0(W[t - 7]) + W[t - 8]);
    }

    uint16_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

    for (int t = 0; t < 32; t++) {
        uint16_t Tx = (SIGMA1(e) + Ch(e, f, g) + W[t]);
        uint16_t Ty = (h + K[t] + d + Tx);
        uint16_t Tz = (SIGMA0(a) + Maj(a, b, c) + (uint16_t)(Ty - d));
        h = g; g = f; f = e; e = Ty;
        d = c; c = b; b = a; a = Tz;
    }

    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

void mini_sha_hash(const char* message, int len, uint16_t* out_H) {
    for (int i = 0; i < 8; i++) out_H[i] = IV[i];
    
    int bytes_processed = 0;
    
    while (len - bytes_processed >= 16) {
        uint16_t block_words[8];
        for (int i = 0; i < 8; i++) {
            block_words[i] = ((uint8_t)message[bytes_processed + 2*i] << 8) | 
                             (uint8_t)message[bytes_processed + 2*i + 1];
        }
        compress(out_H, block_words);
        bytes_processed += 16;
    }
    
    int remaining = len - bytes_processed;
    uint8_t last_blocks[32] = {0}; 
    
    for (int i = 0; i < remaining; i++) {
        last_blocks[i] = message[bytes_processed + i];
    }
    last_blocks[remaining] = 0x80;
    
    int total_padding_len = (remaining >= 14) ? 32 : 16;
    
    uint16_t bits = len * 8;
    last_blocks[total_padding_len - 2] = (bits >> 8) & 0xFF;
    last_blocks[total_padding_len - 1] = bits & 0xFF;
    
    for (int b = 0; b < total_padding_len; b += 16) {
        uint16_t block_words[8];
        for (int i = 0; i < 8; i++) {
            block_words[i] = (last_blocks[b + 2*i] << 8) | last_blocks[b + 2*i + 1];
        }
        compress(out_H, block_words);
    }
}

int main() {
    FILE* f = fopen("build/release/sys_proc.elf", "rb");
    if (!f) {
        printf("Error: Could not open file\n");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* buffer = malloc(size);
    fread(buffer, 1, size, f);
    fclose(f);

    uint16_t hash[8];
    mini_sha_hash(buffer, size, hash);

    printf("Kernel File Size: %ld bytes\n", size);
    printf("Golden Hash (Hex): ");
    for (int i = 0; i < 8; i++) {
        printf("%04x", hash[i]);
    }
    printf("\n");

    printf("Golden Hash (C Array): ");
    for (int i = 0; i < 8; i++) {
        printf("0x%04x%s", hash[i], (i == 7) ? "" : ", ");
    }
    printf("\n");

    free(buffer);
    return 0;
}
