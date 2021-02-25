#ifndef MSHA256_H
#define MSHA256_H

#include "uint_custom.h"
#include <string>
#include <sstream>
#include <iostream>

// attempting to create a sha256 hash algorithm myself with https://qvault.io/2020/07/08/how-sha-2-works-step-by-step-sha-256/
// also used http://www.zedwood.com/article/cpp-sha256-function to identify bad areas.

#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))

// sha256 constants
const unsigned int sha256_k[64] = //UL = uint32
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
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
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

const unsigned int sha256_h[8] =
            {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

class M_sha256 {
public:
    static uint256<256> sha256header(unsigned char* input, int length) {
        uint256<256> hashed = sha256AlgorithmUint256Input(input, length);

        unsigned char digest[32];
        memcpy(&digest, &hashed, 32);

        uint256<256> hashed2 = sha256AlgorithmUint256Input(digest, 32);
        return hashed2;
    }

    static uint256<256> sha256AlgorithmUint256Input(unsigned char* inputorig, int length) {
        // input needs to be divisible by 4
        int intdivision = ((length >> 6) << 6) + 64;
        unsigned char input[intdivision];
        memset(&input, 0x00, intdivision);
        memcpy(&input, inputorig, length);

        int blocks = ((length - (length % 56)) / 56) + 1;
        int i = 0;
        unsigned int schedules[blocks][64];
//        memset(&schedules, 0x00, blocks*64);

        for(int bl = 0; bl < blocks; bl++) {
            // blank all fields
            for(i = 0; i < 64; i++) {
                schedules[bl][i] = 0;
            }

            // this loop amount only works with 2 blocks.
            for(i = 0; i < 16; i++){
                if ((length > 32 && bl > 0 && i > 3) || (length == 32 && i > 7)) {
                    continue;
                }
    //            schedule[i] += prehash[(i*4)] << 16;
                unsigned int one = *(input + (i*4) + (bl * 64)) << 24;
                unsigned int two = *(input + (i*4) + 1 + (bl * 64)) << 16;
                unsigned int three = *(input + (i*4) + 2 + (bl * 64)) << 8;
                unsigned int four = *(input + (i*4) + 3 + (bl * 64));
                schedules[bl][i] = one + two + three + four;
            }

            // add a single bit to end of values
            if (bl+1 == blocks && length > 32) {
                schedules[bl][4] = 0x80000000;
                schedules[bl][15] = length*8;
            } else if ((length == 32) && (bl+1 == blocks)) {
                schedules[bl][8] = 0x80000000;
                schedules[bl][15] = length*8;
            } else if (length < 32) {
                int remains = length % 4;
                schedules[bl][length / 4] += (0x80000000 >> (remains*8));
                schedules[bl][15] = length*8;
            }
        }

        // compression variables
        unsigned int sha256_h_buffer[8] = {sha256_h[0],sha256_h[1],sha256_h[2],sha256_h[3],sha256_h[4],sha256_h[5],sha256_h[6],sha256_h[7]};

        for(int bl = 0; bl < blocks; bl++) {
            // fill the schedule arrays
            for(i = 16; i < 64; i++) {
                // (n >> d)|(n << (int_bits - d))
//                unsigned int s0 = ((schedules[bl][i-15] >> 7)|(schedules[bl][i-15] << 25)) ^ ((schedules[bl][i-15] >> 18)|(schedules[bl][i-15] << 14)) ^ (schedules[bl][i-15] >> 3);
//                unsigned int s1 = ((schedules[bl][i-2] >> 17)|(schedules[bl][i-2] << 15)) ^ ((schedules[bl][i-2] >> 19)|(schedules[bl][i-2] << 13)) ^ (schedules[bl][i-2] >> 10);
//                unsigned int s0 = rightRotate(schedules[bl][i-15], 7, 32) ^ rightRotate(schedules[bl][i-15], 18, 32) ^ (schedules[bl][i-15] >> 3);
//                unsigned int s1 = rightRotate(schedules[bl][i-2], 17, 32) ^ rightRotate(schedules[bl][i-2], 19, 32) ^ (schedules[bl][i-2] >> 10);
//                unsigned int final = schedules[bl][i-16] + s0 + schedules[bl][i-7] + s1;
                // modulo 2^32
    //            schedule[i] = (final - ((final >> 32) & 0xff));
//                schedules[bl][i] = (final << 32) >> 32;
//                schedules[bl][i] = final;
                schedules[bl][i] = schedules[bl][i-16] + schedules[bl][i-7] + SHA256_F4(schedules[bl][i-2]) + SHA256_F3(schedules[bl][i-15]);
            }


            unsigned int a,b,c,d,e,f,g,h;
            a = sha256_h_buffer[0];
            b = sha256_h_buffer[1];
            c = sha256_h_buffer[2];
            d = sha256_h_buffer[3];
            e = sha256_h_buffer[4];
            f = sha256_h_buffer[5];
            g = sha256_h_buffer[6];
            h = sha256_h_buffer[7];

            // COMPRESSION
            for(i = 0; i < 64; i++) {
                // (n >> d)|(n << (int_bits - d))
                //
//                unsigned int s0 = rightRotate(a, 2, 32) ^ rightRotate(a, 13, 32) ^ rightRotate(a, 22, 32);
//                unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
//                unsigned long int temp2 = s0 + maj;
//                unsigned int temp2 = (((a >> 2)|(a << (30))) ^ ((a >> 13)|(a << (19))) ^ ((a >> 22)|(a << (10)))) + ((a & b) ^ (a & c) ^ (b & c));

//                t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
//                    + sha256_k[j] + w[j];
//                t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);

                unsigned int temp2 = SHA256_F1(a) + SHA2_MAJ(a, b, c);

//                unsigned int s1 = rightRotate(e, 6, 32) ^ rightRotate(e, 11, 32) ^ rightRotate(e, 25, 32);
//                unsigned int ch = (e & f) ^ ((~e) & g);

                // modulo needed for loop back if bytes > 64
//                unsigned long int temp1 = h + s1 + ch + sha256_k[i] + schedules[bl][i];
//                unsigned int temp1 = h + s1 + ch + sha256_k[i] + schedules[bl][i];
//                unsigned int temp1 = h + (((e >> 6)|(e << (26))) ^ ((e >> 11)|(e << (21))) ^ ((e >> 25)|(e << (7)))) + ((e & f) ^ ((~e) & g)) + sha256_k[i] + schedules[bl][i];
                unsigned int temp1 = h + SHA256_F2(e) + SHA2_CH(e,f,g) + sha256_k[i] + schedules[bl][i];

                h = g;
                g = f;
                f = e;
//                e = ((unsigned long int)(d + temp1) << 32) >> 32;
                e = d+temp1;
                d = c;
                c = b;
                b = a;
//                a = ((unsigned long int)(temp1 + temp2) << 32) >> 32;
                a = temp1+temp2;
            }

//            sha256_h_buffer[0] = ((unsigned long int)(sha256_h_buffer[0] + a) << 32) >> 32;
//            sha256_h_buffer[1] = ((unsigned long int)(sha256_h_buffer[1] + b) << 32) >> 32;
//            sha256_h_buffer[2] = ((unsigned long int)(sha256_h_buffer[2] + c) << 32) >> 32;
//            sha256_h_buffer[3] = ((unsigned long int)(sha256_h_buffer[3] + d) << 32) >> 32;
//            sha256_h_buffer[4] = ((unsigned long int)(sha256_h_buffer[4] + e) << 32) >> 32;
//            sha256_h_buffer[5] = ((unsigned long int)(sha256_h_buffer[5] + f) << 32) >> 32;
//            sha256_h_buffer[6] = ((unsigned long int)(sha256_h_buffer[6] + g) << 32) >> 32;
//            sha256_h_buffer[7] = ((unsigned long int)(sha256_h_buffer[7] + h) << 32) >> 32;
            sha256_h_buffer[0] += a;
            sha256_h_buffer[1] += b;
            sha256_h_buffer[2] += c;
            sha256_h_buffer[3] += d;
            sha256_h_buffer[4] += e;
            sha256_h_buffer[5] += f;
            sha256_h_buffer[6] += g;
            sha256_h_buffer[7] += h;
        }

        uint256<256> digest;
        digest.write32BitAt(0, sha256_h_buffer[0]);
        digest.write32BitAt(4, sha256_h_buffer[1]);
        digest.write32BitAt(8, sha256_h_buffer[2]);
        digest.write32BitAt(12, sha256_h_buffer[3]);
        digest.write32BitAt(16, sha256_h_buffer[4]);
        digest.write32BitAt(20, sha256_h_buffer[5]);
        digest.write32BitAt(24, sha256_h_buffer[6]);
        digest.write32BitAt(28, sha256_h_buffer[7]);

        return digest;
    }
};

#endif // MSHA256_H
