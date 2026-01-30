#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//#define DEBUG
#define rotr(x,n)     (((x)>>n) | ((x) << (32-n)))    
#define rotl(x,n)     ((x<<n) | ((x) >> (32-n)))    
#define shr(x,n)      ((x)>>n)
#define ch(x,y,z)     (((x)&(y)) ^ ((~x)&(z)))
#define maj(x,y,z)    (((x)&(y)) ^ ((x)&(z)) ^ ((y)&(z)))
#define L_2_B_32B(x)  (((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x & 0xFF0000) >> 8) | ((x & 0xFF000000) >> 24)) 
#define L_2_B_64B(x)  (((x & 0xFF) << 56) | ((x & 0xFF00) << 40) | ((x & 0xFF0000) << 24) | ((x & 0xFF000000) << 8) | ((x & 0xFF00000000000000) >> 56) | ((x & 0x00FF000000000000) >> 40) | ((x & 0x0000FF0000000000) >> 24) | ((x & 0x000000FF00000000) >> 8))
#define L_END         0x1
#define B_END         0x2
#define STA_MSG       0x1
#define STA_PAD1      0x2
#define STA_PAD2      0x3

typedef struct {
    uint32_t orig_len;
    uint32_t pend_len;
    uint32_t msg_offset;
    uint8_t* msg;
    uint32_t status;
}msg_info;

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t H[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

static inline uint32_t sig0(uint32_t x) {
    return (rotr(x,2) ^ rotr(x,13) ^ rotr(x,22));
}

static inline uint32_t sig1(uint32_t x) {
    return (rotr(x,6) ^ rotr(x,11) ^ rotr(x,25));
}

static inline uint32_t rho0(uint32_t x) {
    return (rotr(x,7) ^ rotr(x,18) ^ shr(x,3));
}

static inline uint32_t rho1(uint32_t x) {
    return (rotr(x,17) ^ rotr(x,19) ^ shr(x,10));
}

static inline uint32_t pad_len(uint32_t len) {
    return (len+8) + (64 - ((len+8)%64));
}

static inline uint8_t chk_endianess(void) {
    int tmp = 0x12345678;
    char *tmp_ptr = (char*)&tmp;
    if(*tmp_ptr == 0x78) return L_END;
    else if(*tmp_ptr == 0x12) return B_END;
    else return 0xFF;
}

static inline uint8_t convert_to_hex(char c) {
    if(c >= '0' && c<= '9') {
        return (c-48);
    }
    if(c >= 'A' && c<= 'F') {
        return (c-55);
    }
    if(c >= 'a' && c<= 'f') {
        return (c-87);
    }
    printf("invalid hex character\n");
    return 0;
}

static inline void hexstring_to_array(uint8_t* msg, char* cmd_msg) {
    uint32_t len = strlen(cmd_msg);
    for(int i=0; i<len; i+=2) {
        msg[i/2] = convert_to_hex(cmd_msg[i]) << 4 | convert_to_hex(cmd_msg[i+1]);
    }
}

static inline void fill_bit_len(uint8_t* msg_blk, uint32_t len) {
    uint64_t bitlen = len * 8;
    *(uint64_t*)&msg_blk[56] = L_2_B_64B(bitlen);    
}
static inline void prep_msg_blk(uint8_t* msg_blk, msg_info* info) {
    // if message passed in < 56 byte only 1 block will be processed
    uint32_t len = info->orig_len;
    memset(msg_blk,0,64);
    if(info->orig_len < 56) {
        memcpy(msg_blk,info->msg,len);
        msg_blk[len] = 0x80;
        fill_bit_len(msg_blk,len);
        return;       
    }
    // multiple block scenerio
    uint8_t to_copy = 0;
    if(info->status == STA_MSG) {
        to_copy = info->pend_len>=64 ? 64 : info->pend_len;
        memcpy(msg_blk,info->msg+info->msg_offset,to_copy);
        info->pend_len -= to_copy;
        info->msg_offset += to_copy;
        if(0 == info->pend_len) info->status = STA_PAD1;
    }
    if(info->status == STA_PAD1 && to_copy <64) {
        msg_blk[to_copy] = 0x80;
        if(to_copy ==0 || (64-to_copy)>=9) {
            fill_bit_len(msg_blk,len);
            return;
        }
        if((64-to_copy)<=8) {
            info->status = STA_PAD2;
            return;
        }
    }
    if(info->status == STA_PAD2) {
        fill_bit_len(msg_blk,len);       
    }
}

int main(int argc, char **argv) {
    if(argc != 2) goto err;
    char *cmd_msg = argv[1];
    uint32_t msglen = strlen(cmd_msg)/2;
    if(msglen % 2) goto err;
    uint8_t* msg = (uint8_t*)malloc(msglen);
    if(!msg) goto err;
    hexstring_to_array(msg, cmd_msg);
    uint32_t W[64] = {0};
    uint32_t a,b,c,d,e,f,g,h;
    uint8_t msg_blk[64] = {0};
    uint32_t padded_len = pad_len(msglen);
    uint32_t num_blocks = padded_len/64;
    msg_info info = {.msg = msg, .msg_offset=0, .orig_len = msglen, .pend_len=msglen, .status = STA_MSG};
    for(int i=0; i<num_blocks; i++) {
        prep_msg_blk(msg_blk, &info);
        for(int i=0; i<16; i++) {
            if(1 == chk_endianess())
                W[i] = L_2_B_32B((*(uint32_t*)&msg_blk[4*i]));
            else if(2 == chk_endianess())  
                W[i] = (*(uint32_t*)&msg_blk[4*i]);
            else goto err;
        }
        for(int t=16; t<64;t++) {
            W[t] = rho1(W[t-2]) + W[t-7] + rho0(W[t-15]) + W[t-16];
        }
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        f = H[5];
        g = H[6];
        h = H[7];
        for(int t=0; t<64; t++) {
            uint32_t t1 = h + sig1(e) + ch(e,f,g) + K[t] + W[t];
            uint32_t t2 = sig0(a) + maj(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        H[0] = a + H[0];
        H[1] = b + H[1];
        H[2] = c + H[2];
        H[3] = d + H[3];
        H[4] = e + H[4];
        H[5] = f + H[5];
        H[6] = g + H[6];
        H[7] = h + H[7];
    }
    printf("sha-256 is :\n");
    for(int i=0; i<8; i++) {
        printf("%x", H[i]);
    }
    printf("\n");
    free(msg);
    return 0;
err:
    free(msg);
    printf("error occurred\n");
    return 1;
}