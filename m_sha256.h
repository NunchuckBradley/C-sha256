#ifndef MSHA256_H
#define MSHA256_H

#include "uint_custom.h"
#include <string>
#include <sstream>
#include <iostream>

#pragma GCC optimize("O3")


// attempting to create a sha256 hash algorithm myself with https://qvault.io/2020/07/08/how-sha-2-works-step-by-step-sha-256/
// also used http://www.zedwood.com/article/cpp-sha256-function to identify bad areas.

#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
//#define SHA2_ROTR(x, n)   ((x >> n) | (x << (-n&(sizeof(x)-1))))
//((x >> R)|(x<<(-R&MASK)))
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
    // https://www.geeksforgeeks.org/subtract-two-numbers-without-using-arithmetic-operators/
    static int subtract(int x, int y)
    {
        while (y != 0)
        {
            int borrow = (~x) & y;
            x = x ^ y;
            y = borrow << 1;
        }
        return x;
    }
    static uint256<256> sha256header(unsigned char* input, int length) {
        uint256<256> hashed = sha256Algorithm(input, length);

        unsigned char digest[32];
        memcpy(&digest, &hashed, 32);

        uint256<256> hashed2 = sha256Algorithm(digest, 32);
        return hashed2;
    }

    static uint256<256> sha256Algorithm(unsigned char* inputorig, int length) {
        // input needs to be divisible by 4
        int intdivision = ((length >> 6) << 6) + 64;
        unsigned char input[intdivision];
        memset(&input, 0x00, intdivision);
        memcpy(&input, inputorig, length);

        int blocks = ((length - (length % 56)) / 56) + 1;
        int i = 0;
        unsigned int schedules_orig[blocks][64];

        // compression variables
        unsigned int sha256_h_buffer_orig[8] = {sha256_h[0],sha256_h[1],sha256_h[2],sha256_h[3],sha256_h[4],sha256_h[5],sha256_h[6],sha256_h[7]};
        unsigned int* sha256_h_buffer = sha256_h_buffer_orig;

        for(int bl = 0; bl < blocks; bl++) {
            unsigned int* schedules = schedules_orig[bl];
            // blank all fields
            memset(&schedules[bl], 0x00, 64);

            for(i = 0; i < 16; i++){
//                if (remainingbytes <= i && bl > 0) {
                if ((length > 32 && bl > 0 && i > 3) || (length == 32 && i > 7)) {
                    break;
                }
                // pack into 8 byte/32 bits array
//                memset(&schedules[bl][i], *(input+(i*8)), 8);
                schedules[i] = (*(input + (i << 2) + (bl << 6)) << 24) + (*(input + (i << 2) + 1 + (bl << 6)) << 16) + (*(input + (i << 2) + 2 + (bl << 6)) << 8) + (*(input + (i << 2) + 3 + (bl << 6)));
            }

            // add a single bit to end of values
            if (bl+1 == blocks && length > 32) {
                schedules[4] = 0x80000000;
                schedules[15] = length*8;
            }
            else if ((length == 32) && (bl+1 == blocks)) {
                schedules[8] = 0x80000000;
                schedules[15] = length*8;
            }
            else if (length < 32) {
                int remains = length % 4;
                schedules[length / 4] += (0x80000000 >> (remains*8));
                schedules[15] = length*8;
            }

            // compression
            // fill the schedule arrays
            for(i = 16; i < 64; i++) {
//                unsigned int* s0v = &schedules[i-15];
//                unsigned int* s1v = &schedules[i-2];
//                unsigned int s0 = ((*s0v >> 7)|(*s0v << 25)) ^ ((*s0v >> 18)|(*s0v << 14)) ^ (*s0v >> 3);
//                unsigned int s1 = ((*s1v >> 17)|(*s1v << 15)) ^ ((*s1v >> 19)|(*s1v << 13)) ^ (*s1v >> 10);
//                schedules[i] = schedules[i-16] + s0 + schedules[i-7] + s1;
                schedules[i] = schedules[i-16] + schedules[i-7] + SHA256_F4(schedules[i-2]) + SHA256_F3(schedules[i-15]);
            }

            unsigned int buf[8];
            for(i = 0; i < 8; i++) {
                buf[i] = sha256_h_buffer[i];
            }
            // COMPRESSION
            for(i = 0; i < 64; i++) {
                unsigned int temp2 = SHA256_F1(buf[0]) + SHA2_MAJ(buf[0], buf[1], buf[2]);
                unsigned int temp1 = buf[7] + SHA256_F2(buf[4]) + SHA2_CH(buf[4],buf[5],buf[6]) + sha256_k[i] + schedules[i];
                buf[7] = buf[6];
                buf[6] = buf[5];
                buf[5] = buf[4];
                buf[4] = buf[3]+temp1;
                buf[3] = buf[2];
                buf[2] = buf[1];
                buf[1] = buf[0];
                buf[0] = temp1+temp2;
            }

            for(i = 0; i < 8; i++) {
                sha256_h_buffer[i] += buf[i];
            }
        }


        uint256<256> digest;
        uint256<256>* digestpointer = &digest;
        digestpointer->write32BitAt(0, &sha256_h_buffer[0]);
        digestpointer->write32BitAt(4, &sha256_h_buffer[1]);
        digestpointer->write32BitAt(8, &sha256_h_buffer[2]);
        digestpointer->write32BitAt(12, &sha256_h_buffer[3]);
        digestpointer->write32BitAt(16, &sha256_h_buffer[4]);
        digestpointer->write32BitAt(20, &sha256_h_buffer[5]);
        digestpointer->write32BitAt(24, &sha256_h_buffer[6]);
        digestpointer->write32BitAt(28, &sha256_h_buffer[7]);

        return digest;
    }
};

#endif // MSHA256_H
