#ifndef _SHA_1_H_
#define _SHA_1_H_

typedef unsigned int word32;
typedef unsigned int uint32;

typedef struct {
    uint32 h[5];
    unsigned char block[64];
    int blkused;
    uint32 lenhi, lenlo;
} SHA_State;

void SHA_Init(SHA_State * s);

void SHA_Bytes(SHA_State * s, void *p, int len);
void SHA_Final(SHA_State * s, unsigned char *output);
void SHATransform(word32* digest, word32* block);
void SHATransformA(word32* digest, word32* block);

#endif //_SHA_1_H_ 
