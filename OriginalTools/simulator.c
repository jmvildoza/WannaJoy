#include <windows.h>
#include <stdio.h>
#include <string.h> //for memset()

#include "simulator.h"
#include "SHA-1.h"

rc4state rc4states[8];
int stream_counter = 0;


void clear_stack() {
	//200 bytes cover both CryptGenRandom's and the simulator's 
    //uninitialized stack variables.
	char on_stack[200];
	memset(on_stack, 0, 200);
}

void print_buf(FILE* out, unsigned char* buf, int buf_len) {
	int i;
	for (i = 0; i < buf_len; i++) {
		fprintf(out, "%02X ", buf[i]);
		if (i % 16 == 15)
			fprintf(out, "\n");
	}
	fprintf(out, "\n");
}

void load_buf(FILE* src, unsigned char* buf, int buf_len) {
	int i;
	for (i = 0; i < buf_len; i++) {
		fscanf(src, "%02X ", &buf[i]);
		if (i % 16 == 15)
			fscanf(src, "\n");
	}
}

void memxor(unsigned char* dest, unsigned char* other, int len) {
	int i;
	for (i = 0; i < len; i++)
		dest[i] ^= other[i];
}

void get_next_20_rc4_bytes(unsigned char* buf, int len) {
	int i;
	rc4state * s;
	unsigned char tmp;

	stream_counter = (stream_counter + 1) % 8;
	
	s = &rc4states[stream_counter];
	
	//standard rc4 inlined below:
	for (i = 0; i < len; i++) {
			s->i++;
			s->j += s->state[s->i];
			
			tmp = s->state[s->i];
			s->state[s->i] = s->state[s->j];
			s->state[s->j] = tmp;

			tmp = s->state[s->i] + s->state[s->j];
			buf[i] ^= s->state[tmp];
	}
}

//if src vector is negative, negates it into the dst vector.
//else overwrites five LSBytes of dst with those from replace vector.
//src and dst are 20 bytes long.
void SHA_mod_q(unsigned char* replace, unsigned char* src, unsigned char* dst) {
	
	int i;
	int compare_result = 0;

	//Compare(src, zero_vector, 5) replaced with:
	for (i = 4; i >= 0; i--) {
		int cmp = *(((int*)src) + i);
		if (cmp  < 0)  {
			compare_result = -1;
			break;
		}
		else if (cmp > 0) {
			compare_result = 1;
			break;
		}
	}

	if (compare_result == -1)
		for (i = 0; i < 5; i++)
			dst[i] = replace[i];
	else 
		for (i = 4; i >= 0; i--) {
			int * d = (int*)dst;
			int * s = (int*)src;
			d[i] = -s[i]; // carry not needed here, because we're subtracting from zero.
		}
}

void AddSeeds(unsigned char* summand, unsigned char* dest) {
	
	int i;
	unsigned int* s = (unsigned int*)summand;
	unsigned int* d = (unsigned int*)dest;
	unsigned int tmp;
	unsigned int carry = 1;
	for (i = 0; i < 5; i++) {
		tmp = s[i] + d[i] + carry;
		if (tmp < s[i])
			carry = 1;
		else
			carry = 0;
		d[i] = tmp;
	} 
}

int SimulateCryptGenRandom(unsigned char* buf, int len) {
	unsigned char state[20];
	unsigned char r[20];
	unsigned char temp[20];
	int m;
	SHA_State sha1state;
	int unidentified_constant[5] = {0x0B156C1F5,0x2E4248D5,0x4144A5BD,0x8241CC7,0x903C803F};
	int fips_iv[5] = { 0x1234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210, 0xF0E1D2C3};

	//the state is not cleared in the real CryptGenRandom.
	//memset(state, 0, 20); 

	while (len > 0) {
		get_next_20_rc4_bytes(r, 20);
		
		memxor(state, r, 20);

		SHA_Init(&sha1state);
        //reverse the SHA IV byte order
        memcpy((char*)sha1state.h, (char*)fips_iv, 20); 

		SHA_Bytes(&sha1state, state, 20);
		SHA_Final(&sha1state, temp);

		//how many bytes to copy into the output? 
		m = min(len, 20);

        //RNG16BitStateCheck replaced with:
	    memcpy(buf, temp, m);

		buf += m;
		len -= m;

		SHA_mod_q(temp, (char*)unidentified_constant, r);
		AddSeeds(r, state);
	}//of while

	return 1;
}

void load_rc4_states(FILE * src) {
	int i,segnum;

	for (i = 0; i < 8; i++) {
		fscanf(src, "RC4 State %d\n", &segnum);
		fscanf(src, "Accumulator: 0x%08X\n", &rc4states[i].accumulator);

		load_buf(src, rc4states[i].state, 256);
		
		fscanf(src, "i: %d\n", &rc4states[i].i);
		fscanf(src, "j: %d\n", &rc4states[i].j);
	}
}

void get_stream_counter(FILE * src) {
	int tmp; //ignored
	fscanf(src, "Stream counter: 0x%08X (mod 8: %d)\n", &stream_counter, &tmp);
}
