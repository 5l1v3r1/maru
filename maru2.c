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

void speck(void *in, void *mk, void *out){
    uint64_t i,t,k[4],
            *r=(uint64_t*)out,
            *h=(uint64_t*)in;

    // copy 128-bit plaintext to output
    r[0] = h[0]; r[1] = h[1];
    // copy 256-bit master key to local buffer
    for(i=0;i<4;i++) k[i] = ((uint64_t*)mk)[i];
    
    for(i=0;i<34;i++) {
      // encrypt plaintext
      r[1] = (ROTR64(r[1], 8) + r[0]) ^ k[0],
      r[0] = ROTR64(r[0], 61) ^ r[1], t=k[3],
      
      // create next subkey
      k[3] = (ROTR64(k[1], 8) + k[0]) ^ i,
      k[0] = ROTR64(k[0], 61) ^ k[3],
      k[1] = k[2], k[2] = t;
    }
}

#else

#define ROTR32(v,n)(((v)>>(n))|((v)<<(32-(n))))

// 128-bit keys and 128-bit blocks
void chaskey(void*in,void*mk,void*out) {
    uint64_t *k=(uint64_t*)mk,*r=(uint64_t*)out,*h=(uint64_t*)in;
    uint32_t i,*x=(uint32_t*)r;
    
    // copy plaintext xor key to output 
    for(i=0;i<2;i++) 
      r[i] = h[i] ^ k[i];
    
    // apply 12 rounds of encryption
    for(i=0;i<12;i++) {
      x[0] += x[1],
      x[1]  = ROTR32(x[1], 27) ^ x[0],
      x[2] += x[3],
      x[3]  = ROTR32(x[3], 24) ^ x[2],
      x[2] += x[1],
      x[0] = ROTR32(x[0], 16) + x[3],
      x[3] = ROTR32(x[3], 19) ^ x[0],
      x[1] = ROTR32(x[1], 25) ^ x[2],
      x[2] = ROTR32(x[2], 16);
    }
    // xor ciphertext with key  
    for(i=0;i<2;i++) 
      r[i] ^= k[i];
}

#endif

void maru2(const char *key, uint64_t iv, void *out) {
    union { uint64_t q[2]; uint32_t w[4]; uint8_t b[16]; } c, h;
    union { uint64_t q[4]; uint32_t w[8]; uint8_t b[32]; } m;
    int     len, idx, i, end;

    // initialize H with iv
    h.q[0] = MARU2_INIT_B ^ iv;
    h.q[1] = MARU2_INIT_D ^ iv;
    
    for (idx=0, len=0, end=0; !end; ) {
      // end of string or max len?
      if (key[len]==0 || len==MARU2_MAX_STR) {
        // zero remainder of M
        for(i=idx;i<MARU2_BLK_LEN;i++) m.b[i]=0;
        // add end bit
        m.b[idx] = 0x80;
        // have we space in M for len?
        if (idx >= MARU2_BLK_LEN-4) {
          // no, encrypt H
          MARU2_CRYPT(&h, &m, &c);
          // update H
          h.q[0] ^= c.q[0];
          h.q[1] ^= c.q[1];          
          // zero M
          for(i=0;i<MARU2_BLK_LEN;i++) m.b[i]=0;
        }
        // add total len in bits
        m.w[(MARU2_BLK_LEN/4)-1] = (len * 8);
        idx = MARU2_BLK_LEN;
        end++;
      } else {    
        // add byte to M
        m.b[idx] = (uint8_t)key[len];
        idx++; len++;
      }
      if (idx == MARU2_BLK_LEN) {
        // encrypt H
        MARU2_CRYPT(&h, &m, &c);
        // update H
        h.q[0] ^= c.q[0];
        h.q[1] ^= c.q[1];
        idx = 0;
      }
    }
    for(i=0;i<MARU2_HASH_LEN;i++) 
      ((uint8_t*)out)[i] = h.b[i];   
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

const uint64_t iv_tbl[]=
{ 0x15DF1E4BE5E7970F,    // hex(trunc(frac(sqrt(1/137))*(2^64))) 
  0x15B6B0E361669B16,    // hex(trunc(frac(sqrt(1/139))*(2^64)))
  0x14F8EB16A5984A4E  }; // hex(trunc(frac(sqrt(1/149))*(2^64)))

#ifndef CHASKEY  
const char *api_hash[]=
{ "9858248f2f001b733d34a3101e3a909e",
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
{ "54be451bb469019342f8e59d72c73977",
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

// ./maru -t <128-bit iv> | dieharder -a -g 200
void diehard(uint64_t iv) {
    uint8_t  key[MARU2_MAX_STR+1];
    int      i;
    uint8_t  h[MARU2_HASH_LEN];
    
    memset(key, 1, sizeof(key));

    for (i=0; ; i++) {
      // increment string buffer
      inc_buf(key, MARU2_MAX_STR);
      // generate hash
      maru2((const char*)key, iv, h);
      // write to stdout
      fwrite(&h, sizeof(h), 1, stdout);
    }
}

uint64_t get_iv(const char *s) {
    uint64_t iv;
    
    // if it exceeds max, ignore it
    if (strlen(s) != MARU2_IV_LEN*2) {
      printf ("Invalid iv length. Require 16-byte hexadecimal string\n");
      exit(0);
    }
    // convert hexadecimal value to binary
    if (!hex2bin(&iv, s)) {
      printf ("Failure to convert iv \"%s\" to binary\n", s);
      exit(0);
    }
    return iv;
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
    char       key[MARU2_MAX_STR+1];
    uint8_t    res[MARU2_HASH_LEN], bin[MARU2_HASH_LEN];
    char       opt;
    uint64_t   iv;
    char       *s;
    
    for (i=1; i<argc; i++) {
      if (argv[i][0]=='/' || argv[i][0]=='-') {
        opt=argv[i][1];
        switch(opt) {
          // test mode writes data to stdout
          case 't':
            // we expect initial value 
            s=getparam(argc, argv, &i);
            iv=get_iv(s);
            // test using iv
            diehard(iv);
          default:
            printf ("usage: %s <key> <iv>\n", argv[0]);
            printf ("       %s -t <128-bit iv> | dieharder -a -g 200\n", argv[0]);
            return 0;
        }
      }
    }
    // 
    if (argc==3) {
      memset(key, 0, sizeof(key));
    
      strncpy((char*)key, argv[1], MARU2_MAX_STR);

      iv=get_iv(argv[2]);
      
      maru2((const char*)key, iv, res);
      
      printf ("Maru2 hash = ");
      
      bin2hex(res, MARU2_HASH_LEN);    
    } else {
      for (i=0; i<sizeof(iv_tbl)/sizeof(uint64_t); i++) {
        putchar('\n');
        for (j=0; j<sizeof(api_tbl)/sizeof(char*); j++) {
          hex2bin((void*)&bin, *p++);
          
          // hash string        
          maru2(api_tbl[j], iv_tbl[i], res);    
          
          bin2hex(res, MARU2_HASH_LEN);
          
          equ = memcmp(bin, res, 16)==0;
          printf (" = maru2(\"%s\", %016llx) : %s\n", 
            api_tbl[j], (unsigned long long)iv_tbl[i], 
            equ ? "OK" : "FAIL");
        }
      }
    }
    return 0;
}
#endif

