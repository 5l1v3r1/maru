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

#include "maru.h"

// SPECK-64/128
uint64_t speck(void *mk, uint64_t p) {
    uint32_t k[4], i, t;
    union {
      uint32_t w[2];
      uint64_t q;
    } x;
    
    // copy plaintext to local buffer
    x.q = p;
    
    // copy master key to local buffer
    for(i=0;i<4;i++) k[i]=((uint32_t*)mk)[i];
    
    for(i=0;i<27;i++) {
      // encrypt plaintext
      x.w[0] = (ROTR32(x.w[0], 8) + x.w[1]) ^ k[0],
      x.w[1] =  ROTR32(x.w[1],29) ^ x.w[0], t = k[3],
      
      // create next subkey
      k[3] = (ROTR32(k[1],8)  + k[0]) ^ i,
      k[0] =  ROTR32(k[0],29) ^ k[3],
      k[1] = k[2], k[2] = t;
    }
    // return 64-bit ciphertext
    return x.q;
}

uint64_t maru(const char *api, uint64_t iv) {
    uint64_t h;
    uint32_t len, idx, end, i;
    
    union {
      uint8_t  b[MARU_BLK_LEN];
      uint32_t w[MARU_BLK_LEN/4];
    } m;
    
    // set H to initial value
    h = iv;
    
    for(idx=0, len=0, end=0;!end;) {
      // end of string or max len?
      if(api[len] == 0 || len == MARU_MAX_STR) {
        // zero remainder of M
        for(i=idx;i<MARU_BLK_LEN;i++) m.b[i]=0;
        // store the end bit
        m.b[idx] = 0x80;
        // have we space in M for api length?
        if(idx >= MARU_BLK_LEN - 4) {
          // no, update H with E
          h ^= MARU_CRYPT(&m, h);
          // zero M
          for(i=0;i<MARU_BLK_LEN;i++) m.b[i]=0;
        }
        // store total length in bits
        m.w[(MARU_BLK_LEN/4)-1] = (len * 8);
        idx = MARU_BLK_LEN;
        end++;
      } else {    
        // store character from api string
        m.b[idx] = (uint8_t)api[len]; 
        idx++; len++;
      }
      if(idx == MARU_BLK_LEN) {
        // update H with E
        h ^= MARU_CRYPT(&m, h);
        // reset idx
        idx = 0;
      }
    }  
    return h;
}

#ifdef TEST

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>

const char *api_tbl[]=
{ "CreateProcessA",
  "LoadLibraryA",
  "GetProcAddress",
  "WSASocketA",
  "GetOverlappedResult",
  "WaitForSingleObject",
  "TerminateProcess",
  "CloseHandle"  };

const uint32_t iv_tbl[]=
{ 0xB467369E,    // hex(trunc(frac(sqrt(137))*(2^32)))
  0xCA320B75,    // hex(trunc(frac(sqrt(139))*(2^32)))
  0x34E0D42E  }; // hex(trunc(frac(sqrt(149))*(2^32)))

const char *api_hash[]=
{ "dfa1de9f2ba8bb90", 
  "ca373df6574bb594", 
  "dc6be1f8f896bf39", 
  "6a5e1a9191abf9f9", 
  "f4f085f3b39948ef", 
  "69049dac4d5f0611", 
  "30e1b9c4fd652a0f", 
  "3c70ee014de21690", 

  "1321263095680c87", 
  "6ea346f388a28beb",
  "df623104f7900c12", 
  "1966b0ac553e7432",
  "d46e329d6e9e0bc6", 
  "eeea2f3292ea27c7", 
  "e17428c9c3fb37f6",
  "4674a23abf321378",

  "2b775ce7bb962b8a", 
  "dec1c645b6efb8d4", 
  "62d3ec77dd71caef", 
  "2537e3bdd94a6542",
  "aeb84fbc1c43b36c", 
  "40722f8ef4c72300",
  "075637c9e4bb3222", 
  "06402c602f4ad7a0" };
  
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

// ./maru -t <64-bit iv> | dieharder -a -g 200
void diehard(uint32_t iv) {
    uint8_t  key[MARU_MAX_STR+1];
    int      i;
    uint64_t h;
    
    memset(key, 1, sizeof(key));

    for (i=0; ; i++) {
      // increment string buffer
      inc_buf(key, MARU_MAX_STR);
      // generate hash
      h = maru((const char*)key, iv);
      // write to stdout
      fwrite(&h, sizeof(h), 1, stdout);
    }
}

uint32_t get_iv(const char *s) {
    uint32_t iv;
    
    // if it exceeds max, ignore it
    if (strlen(s) != MARU_IV_LEN*2) {
      printf ("Invalid iv length. Require 8-byte hexadecimal string\n");
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
    uint64_t   h=0, x;
    int        i, j;
    const char **p=api_hash;
    char       key[MARU_MAX_STR+1];
    char       opt;
    char       *s;
    uint32_t   iv=0;
    
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
            return 0;           
          default:
            printf ("usage: %s <key> <iv>\n", argv[0]);
            printf ("       %s -t <64-bit iv> | dieharder -a -g 200\n", argv[0]);
            return 0;
        }
      }
    }
    // no arguments sends keys to stdout
    if (argc==3) {
      memset(key, 0, sizeof(key));
    
      strncpy((char*)key, argv[1], MARU_MAX_STR);

      iv=get_iv(argv[2]);
      
      h = maru((const char*)key, iv);
    
      printf ("\nMaru Hash = %llx\n", (unsigned long long)h);
    } else {
      // for each iv
      for (i=0; i<sizeof(iv_tbl)/sizeof(uint32_t); i++) {
        putchar('\n');      
        // for each API string
        for (j=0; j<sizeof(api_tbl)/sizeof(char*); j++) {
          hex2bin((void*)&h, *p++);
          // test vectors here need to be byte swapped
          h = SWAP64(h);
          // hash string        
          x = maru((const char*)api_tbl[j], iv_tbl[i]);        
          
          printf ("  \"%016llx\", = maru(\"%s\", 0x%08x) : %s\n", 
            (unsigned long long)x, api_tbl[j], iv_tbl[i], 
            (h==x) ? "OK" : "FAIL");
        }
      }
    }
    return 0;
}
#endif

