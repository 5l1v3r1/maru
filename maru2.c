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
  
#include "maru2.h"

#ifdef TEST
void bin2hex(void*, int);
#endif

#ifndef CHASKEY

#define E speck128_encrypt

// 256-bit keys and 128-bit blocks
void speck128_encrypt(const void *in, const void *key, void *out)
{
    uint64_t x0, x1;
    uint64_t k0, k1, k2, k3;
    uint64_t i, t;

    w128_t   *x=(w128_t*)in;
    w128_t   *r=(w128_t*)out;
    w256_t   *k=(w256_t*)key;
    
    // load key
    k0 = k->q[0]; k1 = k->q[1];
    k2 = k->q[2]; k3 = k->q[3];

    // load data
    x0 = x->q[0]; x1 = x->q[1];

    for (i=0; i<34; i++) {
      // encrypt block
      x0 = (ROTR64(x0, 8) + x1) ^ k0;
      x1 =  ROTL64(x1, 3) ^ x0;
      
      // create next subkey
      k1 = (ROTR64(k1, 8) + k0) ^ i;
      k0 =  ROTL64(k0, 3) ^ k1;

      // rotate left 64-bits
      XCHG(k3, k2);
      XCHG(k3, k1);     
    }
    // store result
    r->q[0] = x0; r->q[1] = x1;    
}

#else

#define E chaskey_encrypt

// 128-bit keys and 128-bit blocks

void chaskey_encrypt(const void *in, const void *key, void *out)
{
    int      i;
    uint32_t *v=(uint32_t*)out;
    uint32_t *k=(uint32_t*)key;

    memcpy(out, in, 16);
    
    // pre-whiten
    for (i=0; i<4; i++) {
      v[i] ^= k[i];
    }

    // apply permutation function
    for (i=0; i<12; i++) {
      v[0] += v[1]; 
      v[1]=ROTL32(v[1], 5); 
      v[1] ^= v[0]; 
      v[0]=ROTL32(v[0],16);       
      v[2] += v[3]; 
      v[3]=ROTL32(v[3], 8); 
      v[3] ^= v[2];
      v[0] += v[3]; 
      v[3]=ROTL32(v[3],13); 
      v[3] ^= v[0];
      v[2] += v[1]; 
      v[1]=ROTL32(v[1], 7); 
      v[1] ^= v[2]; 
      v[2]=ROTL32(v[2],16);
    }
    // post-whiten
    for (i=0; i<4; i++) {
      v[i] ^= k[i];
    }
}

#endif

void maru2(const char *key, uint64_t seed, void *out) 
{
    w128_t  h, c;
    w256_t  m;
    int     len, idx, end;

    // initialize H with seed
    h.q[0] = MARU2_INIT_B ^ seed;
    h.q[1] = MARU2_INIT_D ^ seed;
    
    for (idx=0, len=0, end=0; !end; ) {
      // end of string or max len?
      if (key[len]==0 || len==MARU2_KEY_LEN) {
        // zero remainder of M
        memset (&m.b[idx], 0, (MARU2_BLK_LEN - idx));
        // add end bit
        m.b[idx] = 0x80;
        // have we space in M for len?
        if (idx >= MARU2_BLK_LEN-4) {
          // no, encrypt H
          E(&h, &m, &c);
          // update H
          h.q[0] ^= c.q[0];
          h.q[1] ^= c.q[1];          
          // zero M
          memset (m.b, 0, MARU2_BLK_LEN);
        }
        // add total len in bits
        m.w[(MARU2_BLK_LEN/4)-1] = (len * 8);
        idx = MARU2_BLK_LEN;
        end++;
      } else {    
        // add byte to M
        m.b[idx++] = (uint8_t)key[len++];
      }
      if (idx == MARU2_BLK_LEN) {
        // encrypt H
        E(&h, &m, &c);
        // update H
        h.q[0] ^= c.q[0];
        h.q[1] ^= c.q[1];
        idx = 0;
      }
    }
    memcpy(out, &h, sizeof(h));    
}

#ifdef TEST

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>

const char *api_tbl[]=
{ "CreateProcessA",
  "LoadLibrayA",
  "GetProcAddress",
  "WSASocketA",
  "GetOverlappedResult",
  "WaitForSingleObject",
  "TerminateProcess",
  "CloseHandle"  };

const uint64_t seed_tbl[]=
{ 0x15DF1E4BE5E7970F,    // hex(trunc(frac(sqrt(1/137))*(2^64))) 
  0x15B6B0E361669B16,    // hex(trunc(frac(sqrt(1/139))*(2^64)))
  0x14F8EB16A5984A4E  }; // hex(trunc(frac(sqrt(1/149))*(2^64)))

#ifndef CHASKEY  
const char *api_hash[]=
{"f026116e5e0313d4cc47f0cbdc5699ce",
"06cc8da8d772943a8e4207418d0a9c5d",
"4efabe1a0f3ef797fd4aab807e40da29",
"64477f13f7890a67dd6b98b00b4aacae",
"e91b709635e7d4a6458a07f813c7853e",
"e501f9c49f66f53fe0c9a25b33790285",
"69b0e9d96be59fccd965bb2ec7e88e88",
"29ca8db3ecd2d3043556a0a13f7e70ba",

"22499e49aae0a5404773bc0207676aa8",
"8dfed83c24d6959f0dcd10ecae0353da",
"81a04f91e9b83505f7f53623491d1930",
"20439389549f7734737663c50d042a9d",
"1ccf4467936d2d12c0e8255e29a02cd1",
"eacf447db6bcbdb167b46d307eaf011e",
"dceb7bdda1fb4b1d0854385b619aaf28",
"50743057adfcdc2bef36ab2816a51163",

"dac9f623ac7a8bf6751de2b8f7ab0e98",
"a589595037d26f2f2f9a5437b5550117",
"6e4b9e0b2491b2e4c8b6cdcb50867468",
"4d8bb4b3b7972418a5e124a2c05522b2",
"a7c0f50dc720744d7fe6cd3438ac96ba",
"273ef74c77dbcb9ece5994894fc9bdee",
"563b94958d937030c8675b51da26e80d",
"945fe9b6b62a6a920e74ec5d51323af8" };
#else
const char *api_hash[]=
{"54be451bb469019342f8e59d72c73977",
"1785cd6d7c6fca19212a0b9e038383ca",
"568f103d5af848a93b008c7b616efd31",
"b4c7871c02689facfc9d33a52087fc8f",
"1083cdc471478a88fb4ac75d2db480c9",
"503ab74f73f6f6c2fbf3065d190c2f19",
"71b977be78e66fca24afe24fdc8bc198",
"789f0f447d89f56c6a09d35213acf66d",

"b0e3d9c84ab287bbc6160f33d08ff692",
"1d1e1d4f43c40d0a044c442647bf4b55",
"6072eff84649be594bbd091cc93b8951",
"2ba8e61d11fdda163bb07df614dc5d84",
"8ade5c23caf20853c7237f3d4fcdcaf6",
"6da2b4b3ea6feb384f6acabe369e865b",
"1862340516faa957f430f88bdf9ccb06",
"acfd5426d080982464a0804fddfc4042",

"761a74e4141beb06eefeb484278695d4",
"9021b9bf9740181535ea8d4219cec778",
"bf8b48c0b0418701894d72e31259b764",
"7a292cf938788c4655bed14857aa8e38",
"ca64dd43b61615a1007f6f6690d2ef98",
"c00792b2feb4dbad15b0f1aefe1c6b7f",
"75e08a5ddf2559ee0957a6e394abf940",
"39ce169896cfc482f5c96d225d10eeb3" };
#endif
  
uint32_t hex2bin (void *bin, const char *hex) {
    uint32_t len, i;
    uint32_t x;
    uint8_t *p=(uint8_t*)bin;
    
    len = strlen (hex);
    
    if ((len & 1) != 0) {
      return 0; 
    }
    
    for (i=0; i<len; i++) {
      if (isxdigit((int)hex[i]) == 0) {
        return 0; 
      }
    }
    
    for (i=0; i<len / 2; i++) {
      sscanf (&hex[i * 2], "%2x", &x);
      p[i] = (uint8_t)x;
    } 
    return len / 2;
} 

void bin2hex(void *bin, int len)
{
    int     i;
    uint8_t *p=(uint8_t*)bin;
    
    putchar('\"');
    
    for (i=0; i<len; i++) {
      printf ("%02x", p[i]);
    } 
    putchar('\"');
}

void inc_buf(void *buf, int mlen) {
    uint8_t *p = (uint8_t*)buf;
    int     i;
    
    for (i=0; i<mlen; i++) {
      if (++p[i] != 0) {
        break;
      } else {
        p[i] = 1;
      }      
    }  
}

// ./maru -t <128-bit seed> | dieharder -a -g 200
void diehard(uint64_t seed) {
    uint8_t  key[MARU2_KEY_LEN+1];
    int      i;
    uint8_t  h[MARU2_HASH_LEN];
    
    memset(key, 1, sizeof(key));

    for (i=0; ; i++) {
      // increment string buffer
      inc_buf(key, MARU2_KEY_LEN);
      // generate hash
      maru2((const char*)key, seed, h);
      // write to stdout
      fwrite(&h, sizeof(h), 1, stdout);
    }
}

uint64_t get_seed(const char *s) {
    uint64_t seed;
    
    // if it exceeds max, ignore it
    if (strlen(s) != MARU2_SEED_LEN*2) {
      printf ("Invalid seed length. Require 16-byte hexadecimal string\n");
      exit(0);
    }
    // convert hexadecimal value to binary
    if (!hex2bin(&seed, s)) {
      printf ("Failure to convert seed \"%s\" to binary\n", s);
      exit(0);
    }
    return seed;
} 
/**F*****************************************************************/
char* getparam (int argc, char *argv[], int *i)
{
    int n=*i;
    if (argv[n][2] != 0) {
      return &argv[n][2];
    }
    if ((n+1) < argc) {
      *i=n+1;
      return argv[n+1];
    }
    printf ("[ %c%c requires parameter\n", argv[n][0], argv[n][1]);
    exit (0);
}

int main(int argc, char *argv[])
{
    uint64_t   h, x;
    int        i, j, equ;
    const char **p=api_hash;
    char       key[MARU2_KEY_LEN+1];
    uint8_t    res[MARU2_HASH_LEN], bin[MARU2_HASH_LEN];
    char       opt;
    uint64_t   seed;
    char       *s;
    
    for (i=1; i<argc; i++) {
      if (argv[i][0]=='/' || argv[i][0]=='-') {
        opt=argv[i][1];
        switch(opt) {
          // test mode writes data to stdout
          case 't':
            // we expect initial value 
            s=getparam(argc, argv, &i);
            seed=get_seed(s);
            // test using seed
            diehard(seed);
          default:
            printf ("usage: %s <key> <seed>\n", argv[0]);
            printf ("       %s -t <128-bit seed> | dieharder -a -g 200\n", argv[0]);
            return 0;
        }
      }
    }
    // 
    if (argc==3) {
      memset(key, 0, sizeof(key));
    
      strncpy((char*)key, argv[1], MARU2_KEY_LEN);

      seed=get_seed(argv[2]);
      
      maru2((const char*)key, seed, res);
      
      printf ("Maru2 hash = ");
      
      bin2hex(res, MARU2_HASH_LEN);    
    } else {
      for (i=0; i<sizeof(seed_tbl)/sizeof(uint64_t); i++) {
        putchar('\n');
        for (j=0; j<sizeof(api_tbl)/sizeof(char*); j++) {
          hex2bin((void*)&bin, *p++);
          
          // hash string        
          maru2(api_tbl[j], seed_tbl[i], res);    
          
          bin2hex(res, MARU2_HASH_LEN);
          
          equ = memcmp(bin, res, 16)==0;
          printf (" = maru2(\"%s\", %016llx) : %s\n", 
            api_tbl[j], (unsigned long long)seed_tbl[i], 
            equ ? "OK" : "FAIL");
        }
      }
    }
    return 0;
}
#endif

