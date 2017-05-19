
#include <windows.h>
//#include <wincrypt.h> //not needed!
#include <stdio.h>

#include "SHA-1.h"
#include "simulator.h"

extern rc4state rc4states[];
extern int stream_counter;

/*****************************************************************************/

void rewind_rc4_states(int num_bytes) {
	int i;
	rc4state * s;
	unsigned char tmp;

	stream_counter %= 8;

	while (num_bytes > 0) {
		s = &rc4states[stream_counter];

		//each state is rewound by 20 bytes, round-robin	
		for (i = 0; i < 20; i++) {
			//no output - just rewinding
		
        	tmp = s->state[s->i];
			s->state[s->i] = s->state[s->j];
			s->state[s->j] = tmp;

			s->j -= s->state[s->i];
			s->i--;
		}
		stream_counter = (stream_counter + 7) % 8; //decrement but keep positive
		num_bytes -= 20;
	}
}

int main(int argc, char *argv[])
{
	BYTE data[160];		 
	FILE * state_after, * previous_outputs;
	int i;

	state_after = fopen("final_state.txt", "r");
	previous_outputs = fopen("previous_outputs.txt", "w");

	if (!state_after || !previous_outputs) {
		fprintf(stderr, "Failed to open input/output files\n");
		exit(1);
	}
	
   	//load saved rc4 states
  	printf("Loading state from final_state.txt.\n");
	get_stream_counter(state_after);
	load_rc4_states(state_after);

	printf("Rewinding RC4 states from final_state.txt back to the last re-keying.\n");
	rewind_rc4_states(REKEYING_PERIOD);

	printf("Simulating CryptGenRandom after rewinding, output in previous_outputs.txt.\n\n");

	//run a CPGR emulator on the extracted states...
	for (i = 0; i < REKEYING_PERIOD; i += 160) {
		clear_stack();
		SimulateCryptGenRandom(data, 160);	
		print_buf(previous_outputs, data, 160);
	}	
			
	if (fclose(state_after) || fclose(previous_outputs)) {
		fprintf(stderr, "Failed to close input/output files\n");
		exit(1);
	}

    return 0;
}
