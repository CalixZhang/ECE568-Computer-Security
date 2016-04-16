#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

//---------------------------------------------------------------------------------------------------------------------------------------------------------------------
	/* Create an otpauth:// URI and display a QR code that's compatible 
		with Google Authenticator
	*/

	//Account Name
	char encodedAccountName[100];
	strcpy(encodedAccountName,urlEncode(accountName));
	//printf("Debug: After encoding account name, it is: %s\n", encodedAccountName);

	//Issuer
	char encodedIssuer[100];
	strcpy(encodedIssuer, urlEncode(issuer));
	//printf("Debug: After encoding issuer, it is: %s\n", encodedIssuer);

	
	//Secret
	//printf("Debug: For secret_hex, you entered initially: %s\n",secret_hex);
	char newSecret[200];	//secret user put in with padded zeroes
	int i;
	if(strlen(secret_hex)<20)
	{
		//printf("Debug: For secret_hex, strlen is less than 20\n");
		int length = strlen(secret_hex);
		int lengthNeeded = 20 - length;	//as need 20 hex characters
		for(i=0;i<length;i++)
		{
			newSecret[i] = secret_hex[i];
		}

		for(i=length;i<20;i++)
		{
			newSecret[i] = '0';
			
		}
	}

	else
	{
		//printf("Debug: For secret_hex, strlen is NOT less than 20\n");
		strcpy(newSecret, secret_hex);		
	}

	/*
	printf("Debug: After padding, newSecret is:\n");
	for(i=0;i<20;i++)
	{
		printf("%c",newSecret[i]);
	}
	printf("\n");
	*/

	//convert to byte array
    uint8_t myByteArray[10];
    uint8_t  myByteArrayLen= strlen(newSecret);
    for (i = 0; i < (myByteArrayLen / 2); i++) 
    {
        sscanf(newSecret + 2*i, "%02x", &myByteArray[i]);       
    }
    ;

	//Good for debugging
	/*
    printf("Debug:Now CONFIRMING imp: \n");
	for (i = 0; i < 10; i++) 
    {
       printf("bytearray %d: %x\n", i, myByteArray[i]);
    }
    */
    
	//base32_encode(const uint8_t *data, int length, uint8_t *result, int bufSize)
	uint8_t result[20];
	int count;
    count = base32_encode(myByteArray,10,result,20);		
	
	//---------------------------------------------------------------------------------------------------------------------------------------------------------------------

	char buf1[200];
	sprintf(buf1, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", encodedAccountName, encodedIssuer, result);
	displayQRcode(buf1);

	char buf2[200];
	sprintf(buf2, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encodedAccountName, encodedIssuer, result);
	displayQRcode(buf2);

	


	return (0);
}
