/**
  Copyright © 2017 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#ifndef MARU_H
#define MARU_H

#include <string.h>
#include <stdint.h>

#include "macros.h"

#define MARU_KEY_LEN  32 // 256-bit input
#define MARU_BLK_LEN  16 // 128-bit cipher key
#define MARU_HASH_LEN  8 // 64-bit cipher block
#define MARU_SEED_LEN  4 // 32-bit seed

#define MARU_INIT_B  SWAP64(0x316B7D586E478442ULL) // hex(trunc(frac(cbrt(1/139))*(2^64)))
#define MARU_INIT_D  SWAP64(0x80FE410FFD2528DAULL) // hex(or(shr(hex(trunc(cos(1/137)*(2^64)));8);shl(0x80;56)))

#define MARU_INIT_H  MARU_INIT_D

typedef union _w32_t {
  uint8_t  b[4];
  uint32_t w;
} w32_t;

typedef union _w64_t {
  uint8_t  b[8];
  uint32_t w[2];
  uint64_t q; 
} w64_t;

typedef union _w128_t {
  uint8_t  b[16];
  uint32_t w[4];
  uint64_t q[2];  
} w128_t;

typedef union _w256_t {
  uint8_t  b[32];
  uint32_t w[8];
  uint64_t q[4];
} w256_t;

typedef union _w512_t {
  uint8_t  b[64];
  uint32_t w[16];
  uint64_t q[8];
} w512_t;

#ifdef __cplusplus
extern "C" {
#endif

  uint64_t maru (const char*, uint32_t);

#ifdef __cplusplus
}
#endif

#endif
  
