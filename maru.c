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

#define E speck64

#define R(v,n)(((v)>>(n))|((v)<<(32-(n))))
#define F(n)for(i=0;i<n;i++)
typedef unsigned int W;
typedef unsigned long long Q;

// SPECK-64/128
Q speck64(void*mk,void*p){
  W k[4],*x=p,i,t;
  union {W w[2]; Q q;}r;
  
  F(4)k[i]=((W*)mk)[i];
  r.w[0]=x[0],r.w[1]=x[1];
  
  F(27)
    r.w[0]=(R(r.w[0],8)+r.w[1])^*k,
    r.w[1]=R(r.w[1],29)^r.w[0],
    t=k[3],
    k[3]=(R(k[1],8)+*k)^i,
    *k=R(*k,29)^k[3],
    k[1]=k[2],k[2]=t;
    
  return r.q;
}

uint64_t maru(const char *key, uint32_t seed) {
    w64_t    h;
    w128_t   m;
    uint32_t len, idx, end;

    // initialize H with seed
    h.q = MARU_INIT_H ^ seed;
    
    for(idx=0,len=0,end=0;!end;) {
      // end of string or max len?
      if(key[len]==0||len==MARU_KEY_LEN) {
        // zero remainder of M
        memset (&m.b[idx],0,(MARU_BLK_LEN-idx));
        // add end bit
        m.b[idx]=0x80;
        // have we space in M for len?
        if(idx>=MARU_BLK_LEN-4) {
          // no, update H with E
          h.q^=E(&m,&h);
          // zero M
          memset(m.b,0,MARU_BLK_LEN);
        }
        // add total len in bits
        m.w[(MARU_BLK_LEN/4)-1] = (len * 8);
        idx = MARU_BLK_LEN;
        end++;
      } else {    
        // add byte to M
        m.b[idx++] = (uint8_t)key[len++];
      }
      if (idx == MARU_BLK_LEN) {
        // update H with E
        h.q ^= E(&m,&h);
        idx = 0;
      }
    }  
    return h.q;
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

const uint32_t seed_tbl[]=
{ 0xB467369E,    // hex(trunc(frac(sqrt(137))*(2^32)))
  0xCA320B75,    // hex(trunc(frac(sqrt(139))*(2^32)))
  0x34E0D42E  }; // hex(trunc(frac(sqrt(149))*(2^32)))

const char *api_hash[]=
{"e2fb9bb4c3758a47",
"96b79c69c710a521",
"77ef46fd685606d0",
"7f3a4529f4cae9bd",
"1fe2b4022329d506",
"266463b00358a9c1",
"78c81b82d46f0911",
"53ed0f022664badf",

"b2699837d95a5676",
"160b1af43901f372",
"bec9deaea797e972",
"38f6ef3e0533ae3a",
"e7a65274d1119a11",
"1be8cfb13685af69",
"5f5e9ebd5ed563f8",
"ff2506b64ee5b9ea",

"954858cbd57e32d7",
"3e922a5892a9de96",
"ba03d4ccac3317e1",
"cc546fa3b6616aad",
"53c10a7fee4a0e7c",
"491df8b4f6a49d91",
"6dd6dda9dcb1497c",
"6cac5f2c04bd721c" };
  
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

// ./maru -t <64-bit seed> | dieharder -a -g 200
void diehard(uint32_t seed) {
    uint8_t  key[MARU_KEY_LEN+1];
    int      i;
    uint64_t h;
    
    memset(key, 1, sizeof(key));

    for (i=0; ; i++) {
      // increment string buffer
      inc_buf(key, MARU_KEY_LEN);
      // generate hash
      h = maru((const char*)key, seed);
      // write to stdout
      fwrite(&h, sizeof(h), 1, stdout);
    }
}

uint32_t get_seed(const char *s) {
    uint32_t seed;
    
    // if it exceeds max, ignore it
    if (strlen(s) != MARU_SEED_LEN*2) {
      printf ("Invalid seed length. Require 8-byte hexadecimal string\n");
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
    uint64_t   h=0, x;
    int        i, j;
    const char **p=api_hash;
    char       key[MARU_KEY_LEN+1];
    char       opt;
    char       *s;
    uint32_t   seed=0;
    
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
            return 0;           
          default:
            printf ("usage: %s <key> <seed>\n", argv[0]);
            printf ("       %s -t <64-bit seed> | dieharder -a -g 200\n", argv[0]);
            return 0;
        }
      }
    }
    // no arguments sends keys to stdout
    if (argc==3) {
      memset(key, 0, sizeof(key));
    
      strncpy((char*)key, argv[1], MARU_KEY_LEN);

      seed=get_seed(argv[2]);
      
      h = maru((const char*)key, seed);
    
      printf ("\nMaru Hash = %llx\n", (unsigned long long)h);
    } else {
      // for each seed
      for (i=0; i<sizeof(seed_tbl)/sizeof(uint32_t); i++) {
        putchar('\n');      
        // for each API string
        for (j=0; j<sizeof(api_tbl)/sizeof(char*); j++) {
          hex2bin((void*)&h, *p++);
          // test vectors here need to be byte swapped
          h = SWAP64(h);
          // hash string        
          x = maru((const char*)api_tbl[j], seed_tbl[i]);        
          
          printf ("  \"%016llx\", = maru(\"%s\", 0x%08x) : %s\n", 
            (unsigned long long)x, api_tbl[j], seed_tbl[i], 
            (h==x) ? "OK" : "FAIL");
        }
      }
    }
    return 0;
}
#endif

