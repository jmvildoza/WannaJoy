#ifndef _SIMULATOR_H_
#define _SIMULATOR_H_

//The rekeying period is 16384 bytes times the number of states.
//The first 20 bytes from each state are spent on initialization, 
//and the last 20 bytes can't be requested or another rekeying will occur.
//The result is rounded to the nearest multiple of 20 to simplify the code.
#define REKEYING_PERIOD ((16384 - 44) * 8)

typedef struct {
	unsigned int accumulator;
	unsigned char state[256];
	unsigned char i, j;
} rc4state;

extern int stream_counter;
extern rc4state rc4states[];

void clear_stack();
void print_buf(FILE* out, unsigned char* buf, int buf_len);
void get_stream_counter(FILE * src);
void load_buf(FILE* src, unsigned char* buf, int buf_len);
void load_rc4_states(FILE * src);
void memxor(unsigned char* dest, unsigned char* other, int len);

int SimulateCryptGenRandom(unsigned char* buf, int len);
void get_next_20_rc4_bytes(unsigned char* buf, int len);
void SHA_mod_q(unsigned char* replace, unsigned char* src, unsigned char* dst);
void AddSeeds(unsigned char* summand, unsigned char* dest); 

#endif