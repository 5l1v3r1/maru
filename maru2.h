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

#ifndef MARU2_H
#define MARU2_H

#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdio.h>

#define ROTR64(v,n)(((v)>>(n))|((v)<<(64-(n))))

#define MARU2_MAX_STR   64
#define MARU2_HASH_LEN  16
#define MARU2_IV_LEN     8

#ifndef CHASKEY
#define MARU2_CRYPT    speck
#define MARU2_BLK_LEN  32 // 256-bit cipher key
#else
#define MARU2_CRYPT    chaskey
#define MARU2_BLK_LEN  16 // 128-bit cipher key
#endif

#define MARU2_INIT_B  _byteswap_uint64(0x316B7D586E478442ULL) // hex(trunc(frac(cbrt(1/139))*(2^64)))
#define MARU2_INIT_D  _byteswap_uint64(0x80FE410FFD2528DAULL) // hex(or(shr(hex(trunc(cos(1/137)*(2^64)));8);shl(0x80;56)))

#define MARU2_INIT_H  MARU2_INIT_D

#ifdef __cplusplus
extern "C" {
#endif

  void maru2 (const char*, uint64_t, void*);

#ifdef __cplusplus
}
#endif

#endif
  
