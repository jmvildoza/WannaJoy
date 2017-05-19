
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#include "simulator.h"

/*****************************************************************************/

void save_rc4_states(FILE * dest) {
	int i;
    int* rc4_states = *((int**)((void*) 0x7CA1FDFC));
	int* state_ptr;
    int num_states = rc4_states[0];

	for (i = 0; i < num_states; i++) {
		fprintf(dest, "RC4 State %d\n", i);

		state_ptr = (int*)rc4_states[2 + i];

		fprintf(dest, "Accumulator: 0x%08X\n", state_ptr[0]);

		print_buf(dest, ((char*)state_ptr)+28, 256);

		fprintf(dest, "i: %d\n", *(((unsigned char*)state_ptr)+284));
		fprintf(dest, "j: %d\n\n", *(((unsigned char*)state_ptr)+285));
	}
}

void save_stream_counter(FILE * dest) {
	unsigned int stream_counter = *((unsigned int*) 0x7CA1FFA8);
	fprintf (dest, "Stream counter: 0x%08X (mod 8: %d)\n", stream_counter, stream_counter%8);
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	HCRYPTPROV hProv = 0;
	BYTE data[160];
	BOOL bResult;
	FILE * state_before, * state_after, * actual;
	int i;

	//Open output files
	actual = fopen("actual.txt", "w");
	state_before = fopen("initial_state.txt", "w");
	state_after  = fopen("final_state.txt", "w");

	if (!state_before || !state_after || !actual) {
		fprintf(stderr, "Failed to open output files\n");
		exit(1);
	}
	
	// Create a new cryptographic context
	bResult = CryptAcquireContext(
								&hProv,
                                NULL,
                                NULL,
                                PROV_RSA_FULL,
                                0); //the last argument may need to be 
                                	//CRYPT_NEWKEYSET on the first run on a machine
     if (!bResult)
     {
       printf("Unable to initialize: CryptAcquireContext failed with %x\n", GetLastError());
       exit(1);
     }

	//Initialize all 8 RC4 states by requesting 20 random bytes from each
	bResult = CryptGenRandom(hProv, 160, data);
    if (!bResult)
    {
       printf("Unable to initialize: CryptGenRandom failed with %x\n", GetLastError());
       exit(1);
    }
		
   	//extract rc4 states and stream counter
    printf("Recording CryptGenRandom state after initialization in initial_state.txt.\n");
	save_stream_counter(state_before);
	save_rc4_states(state_before);
		
	//run the real CPGR for the next 16KB - 160B...
	printf("Recording CryptGenRandom output in actual_output.txt.\n");
	for (i = 0; i < REKEYING_PERIOD; i += 160) {	
		memset(data, 0, 160); //irrelevant - CryptGenRandom ignores buffer contents
		clear_stack();

		bResult = CryptGenRandom(hProv, 160, data);
        if (!bResult)
   	    {
       	   printf("CryptGenRandom failed with %x\n", GetLastError());
           exit(1);
   	    }		
		print_buf(actual, data, 160);
	}

	printf("Recording CryptGenRandom states after output generation in final_state.txt.\n\n");
	save_stream_counter(state_after);
	save_rc4_states(state_after);
			 
	//cleanup		  
	if (hProv) 
		CryptReleaseContext(hProv, 0);		
			
		if (fclose(actual) || fclose(state_before) || fclose(state_after)) {
				fprintf(stderr, "Failed to close output files\n");
				exit(1);
		}

   	return 0;
}
