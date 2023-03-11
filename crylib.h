#ifndef CRYLIB_H
#define CRYLIB_H

#include <stdio.h>

typedef unsigned char byte_t;


// Hashing
void print_hash(const byte_t* hash, const size_t size);
int sha_256(const byte_t input[], const size_t input_size, byte_t* digest);



#endif