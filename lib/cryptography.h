#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

#ifndef SHA256_H
#define SHA256_H

#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest
#define SHA256_SIZE 32 * 2 + 1

typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD1;             // 32-bit WORD1, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	WORD1 datalen;
	unsigned long long bitlen;
	WORD1 state[8];
} SHA256_CTX;

int sha256(char *message, char *hash);

#endif

#define MD5_BLOCK_SIZE 16
#define MD5_SIZE 16 * 2

typedef struct {
   BYTE data[64];
   WORD1 datalen;
   unsigned long long bitlen;
   WORD1 state[4];
} MD5_CTX;

void printHash(uint32_t *hash);
int sha256(char *message, char *hash);
int md5(char *message, char *hash);
unsigned long DJB2(unsigned char *str);

void hash_to_str(uint32_t *hash, char *hash_str);
void str_to_uint8(char *str, uint8_t *arr);
void uint8_to_str(uint8_t *str, char *arr);
void str_to_uint32(char *str, uint32_t *arr);
void uint32_to_str(uint32_t *str, char *arr);

#endif