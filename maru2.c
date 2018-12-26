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

#define E speck128
#define R(v,n)(((v)>>(n))|((v)<<(64-(n))))
#define F(n)for(i=0;i<n;i++)
typedef unsigned long long W;

void speck128(void*in,void*mk,void*out){
  W i,t,k[4],*r=(W*)out,*h=(W*)in;

  memcpy(r,in,16);
  memcpy(k,mk,32);
  
  F(34)
    r[1]=(R(r[1],8)+*r)^*k,
    *r=R(*r,61)^r[1],
    t=k[3],
    k[3]=(R(k[1],8)+*k)^i,
    *k=R(*k,61)^k[3],
    k[1]=k[2],k[2]=t;
}

#else

#define E chaskey
#define R(v,n)(((v)>>(n))|((v)<<(32-(n))))
#define F(n)for(i=0;i<n;i++)
typedef unsigned long long W;

// 128-bit keys and 128-bit blocks
void chaskey(void*in,void*mk,void*out) {
  W *k=(W*)mk,*r=(W*)out,*h=(W*)in;
  unsigned int i,*x=(unsigned int*)r;
  
  F(2)r[i]=h[i]^k[i];
  
  F(12)
    *x+=x[1],
    x[1]=R(x[1],27)^*x,
    x[2]+=x[3],
    x[3]=R(x[3],24)^x[2],
    x[2]+=x[1],
    *x=R(*x,16)+x[3],
    x[3]=R(x[3],19)^*x,
    x[1]=R(x[1],25)^x[2],
    x[2]=R(x[2],16);
    
  F(2)r[i]^=k[i];
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
{"9858248f2f001b733d34a3101e3a909e",
"ca12cb61de448562e572e37aa55dfb7f",
"498c243e939acb8a9d59c44c6c9f4380",
"01c839fbf214db9524a68a100b1cd754",
"b7f38ae915ecc7335638e89f0cffb583",
"ed0e39aaaa2b3e399d8455cc7505ef93",
"04f7639f7ee9236994b0d28c0fb4b055",
"854cfb2c97c8c18ffcbf95f9c746950c",

"c6228cee2be2b88aacb01f850615eeb3",
"5d2755646a6e085c1d7dc8fa7591682e",
"4fc018eb44a4490bd65954d2df3e398c",
"9a42b9ae9f6a9345b71ae3e353ba3260",
"5f13944a73a86069a7738833222aa7f8",
"cedf16f7531fde6df6d3a37e72fee107",
"c332ea0b843d33e3d59cacbaa45f15c1",
"b4cf1b2866c819f8897ab862399873f4",

"10842cca0875ef4b146a4e41751d91e8",
"1b956c02d01403fc80de0aa8c0fa597a",
"c17bc5a83feec3ececb9a734aab0f287",
"3f2b56fba6cd4dbf5f4f5f1f7b94d273",
"7af936877831f3e7fec329bcd1ff103e",
"268bc439753e41c4b9c48ad9dee43878",
"1a5d81d790bb66d4eda824a87273173b",
"c8d3a074596bff3ec63aabb9402b33b7"};
#else
const char *api_hash[]=
{"54be451bb469019342f8e59d72c73977",
"2ec18e184293e002e7ca996342192e05",
"568f103d5af848a93b008c7b616efd31",
"b4c7871c02689facfc9d33a52087fc8f",
"1083cdc471478a88fb4ac75d2db480c9",
"503ab74f73f6f6c2fbf3065d190c2f19",
"71b977be78e66fca24afe24fdc8bc198",
"1841c661b87fb7e6879621f4f09ca636",

"b0e3d9c84ab287bbc6160f33d08ff692",
"c70033a3855b3cf45fb8c76269bb7083",
"6072eff84649be594bbd091cc93b8951",
"2ba8e61d11fdda163bb07df614dc5d84",
"8ade5c23caf20853c7237f3d4fcdcaf6",
"6da2b4b3ea6feb384f6acabe369e865b",
"1862340516faa957f430f88bdf9ccb06",
"c50ae50471bffe33dbe894fbd025eba4",

"761a74e4141beb06eefeb484278695d4",
"1fdb8c8aa1a5c7a7fcd139462254ae10",
"bf8b48c0b0418701894d72e31259b764",
"7a292cf938788c4655bed14857aa8e38",
"ca64dd43b61615a1007f6f6690d2ef98",
"c00792b2feb4dbad15b0f1aefe1c6b7f",
"75e08a5ddf2559ee0957a6e394abf940",
"be73af81cce67c57a933b934ce8e309f" };
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

