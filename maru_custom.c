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

#define E encrypt

uint64_t encrypt(const void *buf, const void *key)
{
    uint32_t x0, x1;
    uint32_t k0, k1, k2, k3;
    int      i, t;
    w64_t    r;

    w64_t    *x=(w64_t*)buf;
    w128_t   *k=(w128_t*)key;
    
    // load key
    k0 = k->w[0]; k1 = k->w[1];
    k2 = k->w[2]; k3 = k->w[3];

    // load data
    x0 = x->w[0]; x1 = x->w[1];

    for (i=0; i<27; i++) {
      // encrypt block
      x0 = (ROTR32(x0, 8) + x1) ^ k0;
      x1 =  ROTL32(x1, 3) ^ x0;
      
      // create next subkey
      k1 = (ROTR32(k1, 8) + k0) ^ i;
      k0 =  ROTL32(k0, 3) ^ k1;
      
      XCHG(k3, k2);
      XCHG(k3, k1);    
    }
    // store result
    r.w[0] = x0; r.w[1] = x1;
    return r.q;    
}

uint64_t maru(const char *str, const void *key) 
{
    w64_t    h;
    w128_t   k;
    w256_t   m;
    
    int      i;  

    // zero initialize m
    memset(&m, 0, sizeof(m));
    
    // copy API string to m
    for (i=0; str[i] != 0 && i<MARU_STR_LEN; i++) {
      m.b[i] = str[i];
    }
    
    // add end bit
    m.b[MARU_STR_LEN-1] |= 0x80;
    
    // add length in bits
    m.w[2] ^= (i * 8);
    
    // initialize H
    h.q = U8TO64_LITTLE((uint8_t*)key);
   
    // encrypt H using API string as key to derive K
    for (i=0; i<2; i++) {  
      k.q[i] = E(&h, &m.b[i*MARU_BLK_LEN]);
    }    
    // return H encrypted with K
    return E(&h, &k);
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

const char *key_tbl[]=
{ "api_api_",
  "api_key2",
  "api_key3"  };

const char *api_hash[]=
{ "3d1e2f30363a32a0",
"4294f8c38cdc09ea",
"f15d572660514167",
"7c11749bcd625107",
"d73c1e4b52e39bdc",
"782c35cfc32a1aa4",
"0a48d75d33a47f39",
"c5f2d0d7aa154e91",

"0739baac7dd1c2ee",
"f905063d7bb632d7",
"73571dee43ca10ff",
"578f67b02f891f2f",
"f9449d7fd612127a",
"b00e9e722442ebca",
"cca0cd66d5a3e2ef",
"741e0dc3038d4fbb",

"19054f7f9c6451ea",
"ccab84b5f274ce33",
"67dfddc6a4411dd4",
"e95d8657f025bb27",
"c00c1dd9f73d525d",
"7cdb8709841d9ba2",
"f9fbcb1024cbb02d",
"60c78137611a7b15" };
  
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

// ./maru -t | dieharder -a -g 200
void diehard(void) {
    uint8_t  str[MARU_STR_LEN+1];
    uint8_t  key[MARU_KEY_LEN+1];
    int      i;
    uint64_t h=MARU_INIT_H;
    
    memset(str, 1, sizeof(str));
    memcpy(key, &h, sizeof(h));
    
    for (i=0; ; i++) {
      // increment string buffer
      inc_buf(str, MARU_STR_LEN);
      // generate hash
      h = maru((const char*)str, key);
      // write to stdout
      fwrite(&h, sizeof(h), 1, stdout);
    }
}

// ./maru | sort | uniq --count --repeated
void alpha_test(void) {
    char     str[MARU_STR_LEN+1];
    uint8_t  key[MARU_KEY_LEN+1];
    char     alpha[64];
    int      i, j;
    uint64_t h;
    
    // init alpha
    for (i=0; i<26; i++) {
      alpha[i]    = (char)('a' + i);
      alpha[i+26] = (char)('A' + i);
    }

    memset(str, 0, sizeof(str));
    memset(str, 0, sizeof(str));
    
    // do all characters appearing at different indices
    for (i=0; i<sizeof(alpha); i++) {
      // create MARU_STR_LEN variations
      for (j=0; j<MARU_STR_LEN; j++) {
        // initialize string buffer to all 1s
        memset(str, 1, sizeof(str));
        // set string buffer to current character in alphabet
        str[j] = alpha[i];
        // create hash
        h = maru(str, key);
        // write to output
        printf ("%016llx\n", (unsigned long long)h);
      }    
    }
    
    // do all 1 byte characters at first index, rest of bytes are zero
    for (i=0; i<52; i++) {
      // zero initialize string buffer
      memset(str, 0, sizeof(str));
      // set string buffer to current character in alphabet
      str[0] = alpha[i];
      // create hash
      h = maru(str, key);
      // write to output
      printf ("%016llx %s\n", (unsigned long long)h, str);      
    }  
}

// attempt to find collision through brute force
void brute_force(char api_name[], uint8_t api_key[]) {
    int      start, end, max_len, min_len, alpha_len;
    int      api_idx[MARU_STR_LEN+1];
    char     api[MARU_STR_LEN+1];
    uint64_t h, r;
    char     str[MARU_STR_LEN+1];
    uint8_t  key[MARU_KEY_LEN+1];
    char     alpha[64];
    int      i, j;
    
    memset(alpha, 0, sizeof(alpha));
    
    // init alpha
    for (i=0; i<26; i++) {
      alpha[i]    = (char)('a' + i);
      alpha[i+26] = (char)('A' + i);
    }

    alpha_len = strlen(alpha);
    
    // get hash for api name and key
    h = maru(api_name, api_key);
    
    // now try to find collision for it
    memset(api, 0, sizeof(str));
    
    // set min_len to 1
    min_len = 1;
    // set max_len to length of api_name
    max_len = strlen(api_name);
    
    // initialize indices
    for (i=0; i<max_len; i++) {
      api_idx[i] = (i < min_len) ? 0 : -1;
    }
    
    printf ("hash to find %016llx\n", (unsigned long long)h);    
    printf ("starting attack with length %i of %i\n", min_len, max_len);
    
    // now try everything until we reach max
    while (min_len <= max_len) {
      // create password
      for (i = 0;i < min_len;i++) {
        api[i] = alpha[ api_idx[i] ];
      }
      //printf ("trying %s\n", api);
      
      r = maru(api, api_key);
      
      if (r == h) {
        printf ("found collision for %s with %s\n", 
          api_name, api);
      }
      
      // increase index 
      for (i = 0;;i++) {
        if (++api_idx[i] != alpha_len) {
          break;
        }
        // reset
        api_idx[i] = 0;
      }
      // reached min_len?
      if (i == min_len) {
        // increase until we reach max_len
        min_len++;
        if(min_len<=max_len) {
          printf ("length is now at %i of %i\n", min_len, max_len);
        }
      }
    }
}

// attempt to find collision through brute force using 1-255
void brute_force2(const char api_name[], char api_key[]) {
    
    uint8_t  api[MARU_STR_LEN+1], key[MARU_KEY_LEN+1];
    int      min_len, max_len, i;
    uint64_t h, r;

    memset(key, 0, sizeof(key));
    strncpy((char*)key, (char*)api_key, MARU_KEY_LEN);
    
    // get hash for api name and key
    h = maru(api_name, key);
    
    // zero initialize api buffer
    memset(api, 0, sizeof(api));
    
    // set min_len to 1
    min_len = 1;
    // set max_len to length of api_name
    max_len = strlen(api_name);    
    
    printf ("hash to find %016llx\n", (unsigned long long)h);    
    printf ("starting search with length %i of %i\n", min_len, max_len);
    
    api[0] = 1;
    
    // now try everything until we reach max
    while (min_len <= max_len) {
      
      // get hash for this api
      r = maru((const char*)api, key);
      
      // found match?
      if (r == h) {
        printf ("found collision for %s with %s\n", 
          api_name, api);
      }
      
      // increase indices 
      for (i = 0;;i++) {
        // if not zero, break
        if (++api[i] != 0) {
          break;
        }
        // otherwise reset to 1 (maru doesn't accept zero)
        // and continue incrementing
        api[i] = 1;
      }
      // reached min_len this round?
      if (i == min_len) {
        // increase min_len until we reach max_len
        min_len++;
        if(min_len<=max_len) {
          printf ("length is now at %i of %i\n", min_len, max_len);
        }
      }
    }    
}

int main(int argc, char *argv[])
{
  uint64_t   h, x;
  int        i, j;
  const char **p=api_hash;
  char       str[MARU_STR_LEN+1];
  char       key[MARU_KEY_LEN+1];
  char       opt;
  
  for (i=1; i<argc; i++) {
    if (argv[i][0]=='/' || argv[i][0]=='-') {
      opt=argv[i][1];
      switch(opt) {
        // test mode writes data to stdout
        case 't':
          diehard();
          return 0;
        // alpha test with different indices  
        case 'a':
          alpha_test();
          return 0;
        // brute force API using alpha [a-z, A-Z]  
        case 'b':
          brute_force(argv[i+1], argv[i+2]);
          return 0;
        // brute force API using 1-255  
        case 'c':
          brute_force2(argv[i+1], argv[i+2]);
          return 0;            
        default:
          printf ("usage: %s <string> <key>\n", argv[0]);
          printf ("       %s -t | dieharder -a -g 200\n", argv[0]);
          printf ("       %s -b <api> <key\n", argv[0]);
          printf ("       %s -c <api> <key\n", argv[0]);
          return 0;
      }
    }
  }
  // no arguments sends keys to stdout
  if (argc==3) {
    memset(str, 0, sizeof(str));
    memset(key, 0, sizeof(key));
  
    strncpy((char*)str, argv[1], MARU_STR_LEN);
    strncpy((char*)key, argv[2], MARU_KEY_LEN); 

    h = maru((const char*)str, key);
  
    printf ("\nMaru Hash = %llx\n", (unsigned long long)h);
  } else {
    for (i=0; i<sizeof(key_tbl)/sizeof(char*); i++) {
      putchar('\n');      
      for (j=0; j<sizeof(api_tbl)/sizeof(char*); j++) {
        hex2bin((void*)&h, *p++);
        // test vectors here need to be byte swapped
        h = SWAP64(h);
        // zero init key
        memset(key, 0, sizeof(key));
        // copy key
        strncpy((char*)key, key_tbl[i], MARU_KEY_LEN);
        // hash string        
        x = maru((const char*)api_tbl[j], key);        
        
        printf ("  \"%016llx\", = maru(\"%s\", \"%s\") : %s\n", 
          (unsigned long long)x, api_tbl[j], key, 
          (h==x) ? "OK" : "FAIL");
      }
    }
  }
  return 0;
}
#endif


