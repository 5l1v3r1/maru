/**
  Copyright � 2017 Odzhan. All Rights Reserved.

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

#include <stdint.h>

#define MARU_MAX_STR  64
#define MARU_BLK_LEN  16
#define MARU_HASH_LEN  8
#define MARU_IV_LEN    MARU_HASH_LEN
#define MARU_CRYPT     speck

#ifndef ROTR32
#define ROTR32(v,n)(((v)>>(n))|((v)<<(32-(n))))
#endif

#ifndef SWAP64
#ifdef _MSC_VER
#define SWAP64(x) _byteswap_uint64(x)
#else
#define SWAP64(x) __builtin_bswap64(x)
#endif
#endif

#define MARU_INIT_B SWAP64(0x316B7D586E478442ULL) // hex(trunc(frac(cbrt(1/139))*(2^64)))
#define MARU_INIT_D SWAP64(0x80FE410FFD2528DAULL) // hex(or(shr(hex(trunc(cos(1/137)*(2^64)));8);shl(0x80;56)))

#ifdef __cplusplus
extern "C" {
#endif

uint64_t maru(const char *api, uint64_t iv);

#ifdef __cplusplus
}
#endif

#endif
  
