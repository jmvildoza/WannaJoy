
#include "SHA-1.h"

//Leo: changes to compile this code under Windows
#define DWORD unsigned int
#include <string.h>		  
//end of

#define MCmp(Param1,Param2,Flag,Loop) \
	__asm cmp Param1,Param2 \
	__asm j##Flag Loop

#define MDec(Param1,Flag,Loop) \
	__asm dec Param1 \
	__asm j##Flag Loop

#define SHA1_FF(A,B,C,D,E,F) \
	__asm mov F,A \
	__asm rol F,5 \
	__asm lea E,[E+F+0x5a827999] \
	__asm add E,[ebp] \
	__asm add ebp,4 \
	__asm mov F,C \
	__asm xor C,D \
	__asm and C,B \
	__asm xor C,D \
	__asm add E,C \
	__asm mov C,F \
	__asm rol B,30

#define SHA1_GG(A,B,C,D,E,F) \
	__asm mov F,A \
	__asm rol F,5 \
	__asm lea E,[E+F+0x6ed9eba1] \
	__asm add E,[ebp] \
	__asm add ebp,4 \
	__asm mov F,C \
	__asm xor C,D \
	__asm xor C,B \
	__asm add E,C \
	__asm mov C,F \
	__asm rol B,30

#define SHA1_HH(A,B,C,D,E,F) \
	__asm mov F,A \
	__asm rol F,5 \
	__asm lea E,[E+F+0x8f1bbcdc] \
	__asm add E,[ebp] \
	__asm add ebp,4 \
	__asm push ebp \
	__asm mov F,B \
	__asm mov ebp,B \
	__asm and F,C \
	__asm and ebp,D \
	__asm or F,ebp \
	__asm mov ebp,C \
	__asm and ebp,D \
	__asm or F,ebp \
	__asm add E,F \
	__asm pop ebp \
	__asm rol B,30

#define SHA1_II(A,B,C,D,E,F) \
	__asm mov F,A \
	__asm rol F,5 \
	__asm lea E,[E+F+0xca62c1d6] \
	__asm add E,[ebp] \
	__asm add ebp,4 \
	__asm mov F,C \
	__asm xor C,D \
	__asm xor C,B \
	__asm add E,C \
	__asm mov C,F \
	__asm rol B,30

void SHATransform(word32* digest, word32* block)
{
	DWORD Bufer[80];

	__asm
	{
	pushad

	lea edi,Bufer
	mov esi,block
	mov ecx,16
	rep movsd

	mov edi,digest
	push ebp
	lea ebp,Bufer

	mov ecx,16
L1:	mov eax,[ebp+ecx*4-3*4]
	xor eax,[ebp+ecx*4-8*4]
	xor eax,[ebp+ecx*4-14*4]
	xor eax,[ebp+ecx*4-16*4]
	rol eax,1
	mov [ebp+ecx*4],eax
	inc ecx
	MCmp(ecx,80,NE,L1)

	mov eax,[edi+0]
	mov ebx,[edi+4]
	mov ecx,[edi+8]
	mov edx,[edi+12]
	mov esi,[edi+16]

	push 4
L3:	SHA1_FF(eax,ebx,ecx,edx,esi,edi)
	SHA1_FF(esi,eax,ebx,ecx,edx,edi)
	SHA1_FF(edx,esi,eax,ebx,ecx,edi)
	SHA1_FF(ecx,edx,esi,eax,ebx,edi)
	SHA1_FF(ebx,ecx,edx,esi,eax,edi)
	MDec(dword ptr[esp],NZ,L3)

	push 4
L4:	SHA1_GG(eax,ebx,ecx,edx,esi,edi)
	SHA1_GG(esi,eax,ebx,ecx,edx,edi)
	SHA1_GG(edx,esi,eax,ebx,ecx,edi)
	SHA1_GG(ecx,edx,esi,eax,ebx,edi)
	SHA1_GG(ebx,ecx,edx,esi,eax,edi)
	MDec(dword ptr[esp],NZ,L4)

	push 4
L5:	SHA1_HH(eax,ebx,ecx,edx,esi,edi)
	SHA1_HH(esi,eax,ebx,ecx,edx,edi)
	SHA1_HH(edx,esi,eax,ebx,ecx,edi)
	SHA1_HH(ecx,edx,esi,eax,ebx,edi)
	SHA1_HH(ebx,ecx,edx,esi,eax,edi)
	MDec(dword ptr[esp],NZ,L5)

	push 4
L6:	SHA1_II(eax,ebx,ecx,edx,esi,edi)
	SHA1_II(esi,eax,ebx,ecx,edx,edi)
	SHA1_II(edx,esi,eax,ebx,ecx,edi)
	SHA1_II(ecx,edx,esi,eax,ebx,edi)
	SHA1_II(ebx,ecx,edx,esi,eax,edi)
	MDec(dword ptr[esp],NZ,L6)

	add esp,16
	pop ebp

	mov edi,digest

	add eax,[edi]
	add ebx,[edi+4]
	add ecx,[edi+8]
	add edx,[edi+12]
	add esi,[edi+16]

	mov [edi],eax
	mov [edi+4],ebx
	mov [edi+8],ecx
	mov [edi+12],edx
	mov [edi+16],esi

	popad
	}
}

void SHA_Init(SHA_State * s)
{	   
    s->h[0] = 0x67452301;
    s->h[1] = 0xefcdab89;
    s->h[2] = 0x98badcfe;
    s->h[3] = 0x10325476;
    s->h[4] = 0xc3d2e1f0;

    s->blkused = 0;
    s->lenhi = s->lenlo = 0;
}

void SHA_Bytes(SHA_State * s, void *p, int len)
{
    unsigned char *q = (unsigned char *) p;
    uint32 wordblock[16];
    uint32 lenw = len;
    int i;

    s->lenlo += lenw;
    s->lenhi += (s->lenlo < lenw);

    if (s->blkused && s->blkused + len < 64) {

	memcpy(s->block + s->blkused, q, len);
	s->blkused += len;
    } else {

	while (s->blkused + len >= 64) {
	    memcpy(s->block + s->blkused, q, 64 - s->blkused);
	    q += 64 - s->blkused;
	    len -= 64 - s->blkused;

	    for (i = 0; i < 16; i++) {
		wordblock[i] =
		    (((uint32) s->block[i * 4 + 0]) << 24) |
		    (((uint32) s->block[i * 4 + 1]) << 16) |
		    (((uint32) s->block[i * 4 + 2]) << 8) |
		    (((uint32) s->block[i * 4 + 3]) << 0);
	    }
	    SHATransform(s->h, wordblock);
	    s->blkused = 0;
	}
	memcpy(s->block, q, len);
	s->blkused = len;
    }
}

void SHA_Final(SHA_State * s, unsigned char *output)
{
    int i;
    int pad;
    unsigned char c[64];
    uint32 lenhi, lenlo;

    if (s->blkused >= 56)
	pad = 56 + 64 - s->blkused;
    else
	pad = 56 - s->blkused;

    lenhi = (s->lenhi << 3) | (s->lenlo >> (32 - 3));
    lenlo = (s->lenlo << 3);

    memset(c, 0, pad);
    c[0] = 0x80;
    SHA_Bytes(s, &c, pad);

    c[0] = (lenhi >> 24) & 0xFF;
    c[1] = (lenhi >> 16) & 0xFF;
    c[2] = (lenhi >> 8) & 0xFF;
    c[3] = (lenhi >> 0) & 0xFF;
    c[4] = (lenlo >> 24) & 0xFF;
    c[5] = (lenlo >> 16) & 0xFF;
    c[6] = (lenlo >> 8) & 0xFF;
    c[7] = (lenlo >> 0) & 0xFF;

    SHA_Bytes(s, &c, 8);

    for (i = 0; i < 5; i++) {
	output[i * 4] = (s->h[i] >> 24) & 0xFF;
	output[i * 4 + 1] = (s->h[i] >> 16) & 0xFF;
	output[i * 4 + 2] = (s->h[i] >> 8) & 0xFF;
	output[i * 4 + 3] = (s->h[i]) & 0xFF;
    }
}
