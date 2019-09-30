#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include "sha256.h"

/*
 * 45%3 gives remainder of 45/3;
 * But division is a slow process.
 * 
 * In case, if the divisor is the form of 2^n,
 * (x % 2^n) = (x & ((2^n)-1)).
 * 
 * During SHA caluclation we need to do operations like (x % 2^6) and
 * (x % 2^32); Thus defined mod4 = 2^4-1, mod6 = 2^6-1 and mod32 = 2^32-1.
 */
static const uint32_t mod4 = 0xF;
static const uint32_t mod6 = 0x3F;
static const uint32_t mod32 = 0xFFFFFFFF;

/* 
 * 'h' key.
 * (first 32 bits of the fractional parts of the square roots of the first 8
 * primes 2..19). 
 */
static const uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

/* 
 * 'k' key.
 * (first 32 bits of the fractional parts of the cube roots of the first
 * 64 primes 2..311).
 */
static const uint32_t k[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
                                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

/*----------------------------------------------------------------------------*/
static uint32_t right_rotate_u32bit( const uint32_t w, const unsigned short num ){
  return ((w >> num) | ( w << ( 32 - num ) ));
}
/*----------------------------------------------------------------------------*/
static void msg_preprocess(
                           const unsigned char *original_msg,
                           unsigned char **final_msg,
                           uint64_t *final_len
                          ){
        uint64_t original_len = 0x0;
	uint64_t original_bit_len = 0x0;
        uint64_t len = 0x0;
        uint64_t i;
        uint64_t k;

  for( original_len=0; original_msg[original_len] != '\0'; original_len++);
  /*
   * msg_len is length of original message in bytes.
   * len is measured in bytes.
   * len = 1, thus 8 bits.
   * msg len should be multiple of 512 bits.
   * hence len should be multiple of 64.
   * 1 byte added to pad 0x80.
   * k bytes needed to pad '0' bits.
   * 8 bytes needed to pad length of message in binary. (64 bits)
   * 1 byte to add null character.
   * Thus, len = msg_len + 1 + k + 8 + 1
   */

  original_bit_len = original_len * 8;

  k = ((original_len + 9) & mod6);
  
  /*
   * if k=0, means no padding of '0' bits are required. But `64-k` will return
   * 64. Thus we took modulo.
   */
  k = (64-k) & mod6;
  
  unsigned char *msg = (unsigned char*)malloc(original_len + 10 + k);

  len = original_len+1+k;

  for(i=0; i<original_len ; i++)
    msg[i] = original_msg[i];

  msg[i] = (unsigned char)((0x80)& 0xFF);

  for(i+=1 ; i<len; i++)
    msg[i] = 0x0;

  len = len + 8;
  i = len;
  msg[i--] = '\0';
  msg[i--] = (unsigned char)original_bit_len;
  msg[i--] = (unsigned char)(original_bit_len >> 8);
  msg[i--] = (unsigned char)(original_bit_len >> 16);
  msg[i--] = (unsigned char)(original_bit_len >> 24);
  msg[i--] = (unsigned char)(original_bit_len >> 32);
  msg[i--] = (unsigned char)(original_bit_len >> 40);
  msg[i--] = (unsigned char)(original_bit_len >> 48);
  msg[i--] = (unsigned char)(original_bit_len >> 56);

  *final_msg = msg;
  *final_len = len;
}
/*----------------------------------------------------------------------------*/

static unsigned char four_bits_to_hex( const uint32_t x ){
  if(x==0)
    return '0';

  else if(x==1)
    return '1';

  else if(x==2)
    return '2';

  else if(x==3)
    return '3';

  else if(x==4)
    return '4';

  else if(x==5)
    return '5';

  else if(x==6)
    return '6';

  else if(x==7)
    return '7';

  else if(x==8)
    return '8';

  else if(x==9)
    return '9';

  else if(x==10)
    return 'A';

  else if(x==11)
    return 'B';

  else if(x==12)
    return 'C';

  else if(x==13)
    return 'D';

  else if(x==14)
    return 'E';

  else if(x==15)
    return 'F';

  else
    return '\0'; 
}

/*----------------------------------------------------------------------------*/
void calculate_sha256( const unsigned char *original_msg ){
        uint32_t sigma0, sigma1, Sigma0, Sigma1, choice, majority, temp1, temp2;
        uint32_t ha[8];
        uint32_t abcdefgh[8];
        uint32_t w[64];

        unsigned char *msg = NULL;
        uint64_t len;

        uint64_t i , j, chunk, m, n;

  sha256sum[64] = '\0';

  msg_preprocess(original_msg , &msg, &len);

  /* Copy the 'h' keys into 'ha'(will contain hash) and 'abcdefgh'. */
  for( i=0; i<8; i++)
    ha[i] = h[i];

  chunk = (len)>>6;
  n = 0;
  for( m=0; m<chunk; m++){
    for(i=0; i<16; i++){
      w[i] = ((msg[n] << 24) | (msg[n+1] << 16) | (msg[n+2] << 8) | msg[n+3]) ;
      n += 4;
    }

    for( i=16; i<64; i++){
      sigma0 = (right_rotate_u32bit(w[i-15],7)) ^ \
               (right_rotate_u32bit(w[i-15],18)) ^ \
               (w[i-15] >> 3);

      sigma1 = (right_rotate_u32bit(w[i-2],17)) ^ \
               (right_rotate_u32bit(w[i-2],19)) ^ \
               (w[i-2] >> 10);

      w[i] = ((w[i-16] + sigma0 + w[i-7] + sigma1) & mod32);
    }

    for( i=0; i<8; i++ )
      abcdefgh[i] = ha[i];

    for( i=0; i<64; i++){
      Sigma1 = right_rotate_u32bit(abcdefgh[4], 6) ^ \
               right_rotate_u32bit(abcdefgh[4], 11) ^ \
               right_rotate_u32bit(abcdefgh[4], 25);

      choice = (abcdefgh[4] & abcdefgh[5]) ^ ((~abcdefgh[4]) & abcdefgh[6]);
      
      temp1 = ((Sigma1 + ((abcdefgh[7] + choice + \
              ((k[i] + w[i]) & mod32)) & mod32)) & mod32);

      Sigma0 = right_rotate_u32bit(abcdefgh[0],2) ^ \
               right_rotate_u32bit(abcdefgh[0],13) ^ \
               right_rotate_u32bit(abcdefgh[0],22);
      
      majority = (abcdefgh[0] & abcdefgh[1]) ^ \
                 (abcdefgh[0] & abcdefgh[2]) ^ \
                 (abcdefgh[1] & abcdefgh[2]);

      temp2 = majority + Sigma0;

      abcdefgh[7] = abcdefgh[6];
      abcdefgh[6] = abcdefgh[5];
      abcdefgh[5] = abcdefgh[4];
      abcdefgh[4] = ((abcdefgh[3] + temp1) & mod32);
      abcdefgh[3] = abcdefgh[2];
      abcdefgh[2] = abcdefgh[1];
      abcdefgh[1] = abcdefgh[0];
      abcdefgh[0] = ((((temp1 + majority) & mod32) + Sigma0) & mod32);
    }

    for( i=0; i<8; i++)
      ha[i] = (ha[i] + abcdefgh[i]) & mod32;
  }


  for(n=0,i=0; i<8; i++){
    for(j=0; j<8; j++){
      sha256sum[n++] = four_bits_to_hex( ( (ha[i] >> ((7-j)*4))) & mod4 );
    }
  }
  
  /* 
   * Free the message variable created dynamically to store post processed
   * message.
   */
  free(msg);
 
}
/*----------------------------------------------------------------------------*/
