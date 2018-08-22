# About

**## WARNING: This is not a cryptographic hash algorithm, and should not be used for anything requiring a strong hash function. ##**

Maru (*Ma-roo*) is a non-cryptographic hash function written specifically to demonstrate the use of key based hash functions in *Position Independent Code* (PIC)

Maru 1 for 32-bit architectures uses the Speck Block cipher with 64-bit block length, and 128-bit key as parameters.

Maru 2 for 64-bit architecture also uses the Speck Block cipher with 128-bit block length, and 256-bit key as parameters. 

The Davies-Meyer construction is used to derive a hash of input.

![](https://github.com/odzhan/maru/blob/master/img/dm_simple.png)

The Davies–Meyer single-block-length compression function feeds each block of the message (mi) as the key to a block cipher. 

It feeds the previous hash value (Hi-1) as the plain text to be encrypted. The output cipher text is then also XORed with the previous hash value (Hi-1) to produce the next hash value (Hi). 

In the first round when there is no previous hash value it uses a constant pre-specified initial value (H0). 

# Prototypes

Maru 1 is ideal for 32-bit architectures. Takes a string as first parameter, and seed as the second.

Expects ***key*** to be a null terminated string not exceeding 32 bytes, and ***seed*** to be 32-bit value used to randomize value of hashes.

It will return a 64-bit hash.

	uint64_t maru (const char* key, uint32_t seed);
  
Maru 2 is ideal for 64-bit architectures. Takes a string as first parameter, seed as second, and output buffer as third.

Expects ***key*** to be a null terminated string not exceeding 64 bytes, and **seed** to be 64-bit value used to randomize value of hashes.

The ***out*** parameter should point to buffer big enough to hold the 16-byte hash.
  
	void maru2 (const char* str, uint64_t seed, void *out);

# Compiling

For MSVC users, type: **nmake msvc**

For GNU C, type: **make gnu**

For Clang, type: **make clang**

# License

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
  POSSIBILITY OF SUCH DAMAGE.

# Maru

This is Maru the cat.

![](https://github.com/odzhan/maru/blob/master/img/maru_cat.png)
