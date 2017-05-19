
#include <windows.h>
//#include <wincrypt.h> //not needed!
#include <stdio.h>
#include "SHA-1.h"

#include "simulator.h"


//extern rc4state rc4states[];
//extern int stream_counter;

/*******************************************************/

int main(int argc, char *argv[])
{
	BYTE data[160];
	FILE * state_before, * next_outputs;

	int i;

	state_before = fopen("initial_state.txt", "r");
	next_outputs = fopen("next_outputs.txt", "w");

	if (!state_before || !next_outputs) {
		fprintf(stderr, "Failed to open input/output files\n");
		exit(1);
	}
	
   	//load rc4 states
	printf("Loading state from initial_state.txt.\n");
    
	get_stream_counter(state_before);
	load_rc4_states(state_before);

	//run simulator to produce output from the loaded states
	printf("Simulating CryptGenRandom from initial state, output in next_outputs.txt.\n\n");

	for (i = 0; i < REKEYING_PERIOD; i += 160) {
		clear_stack();
		SimulateCryptGenRandom(data, 160); 
		print_buf(next_outputs, data, 160);
	}	
			
	if (fclose(state_before) || fclose(next_outputs)) {
		fprintf(stderr, "Failed to close input/output files\n");
		exit(1);
	}

    return 0;
}
