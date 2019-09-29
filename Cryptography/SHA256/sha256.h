#include <stdint.h>

#ifndef _SHA256_H_
#define _SHA256_H_

/*
 * The final SHA256 Sum is stored in this variable.
 */
unsigned char sha256sum[65];

void calculate_sha256( const unsigned char* );

#endif