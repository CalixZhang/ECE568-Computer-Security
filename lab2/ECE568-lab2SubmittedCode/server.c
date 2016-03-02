// Good reference - http://www.thegeekstuff.com/2011/12/c-socket-programming/

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sslfunctions.h"

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

//my defined functions
int setup_tcp(int port);
void read_write_server( SSL *ssl, int s);
void print_client_certification(SSL *ssl);


//my defined constants
#define SERVERKEYFILE "bob.pem"
#define SERVERPASSWORD "password"



//-------------------------------------------------------------------Main----------------------------------------------------------------------
int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  pid_t pid;  //The pid_t data type is a signed integer type which is capable of representing a process ID. In the GNU library, this is an int.
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1: //if 1 arg, then use default port
      break;
    case 2: //if 2 args, then use port number specified
      port=atoi(argv[1]);
      if (port<1||port>65535){
	       fprintf(stderr,"invalid port number");
	       exit(0);
      }
      break;
    default:  //if random number of args, then print this message and exit
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  //Initialization of ssl stuff
  SSL_CTX *ctx; 
  SSL *ssl; 
  BIO *sbio;
  
  int r;

  //Context Initializaton: load our own keys
  ctx = initialize_ctx(SERVERKEYFILE, SERVERPASSWORD);
  
  //set cipher list
  SSL_CTX_set_cipher_list(ctx, "SSLv2:SSLv3:TLSv1");

  //set verification mode for all to certificate based - TODO: unsure
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

  sock = setup_tcp(port);
  //printf("Server is listening on port %d...\n",port);
  
  while(1){
    
    //wait for new connections
    //It returns a new file descriptor, and all communication on this connection should be done using the new file descriptor.
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /*Then fork a child to handle the connection*/

    if((pid=fork())){ //if parent
      close(s);
    }

    else {
      /*Child code*/

      //Create and set up a new SSL structure
      ssl = SSL_new(ctx);
      sbio = BIO_new_socket(s,BIO_NOCLOSE); //read and write socket BIO
      SSL_set_bio(ssl,sbio,sbio);

      //Initiate the SSL handshake with a client
      //printf("Initiating SSL handshake on server side:\n");
      r = SSL_accept(ssl);
      //printf ("SSL accept code: %d \n", r);
      if(r<=0) {
    	switch(SSL_get_error(ssl, r)) {
    		case SSL_ERROR_NONE:
    			//printf("ssl_error_none\n");
    			break;
    		case SSL_ERROR_ZERO_RETURN:
    			//printf("ssl_error_zero_return\n");
    			break;
    		case SSL_ERROR_SYSCALL:
    			//printf("ssl_error_syscall\n");
    			break;
    		case SSL_ERROR_SSL:
    			//printf("ssl_error_ssl\n");
    			break;
    		case SSL_ERROR_WANT_READ:
    			//printf("ssl_error_want_read\n");
    			break;
    		default:
    			printf("unknown error!\n");
    			break;
	     }
			 
        //printf ("SSL accept error code: %d \n", r);
        printf(FMT_ACCEPT_ERR);
        ERR_print_errors_fp(stdout);  //unsure
        //berr_exit(FMT_ACCEPT_ERR);
        close(s);
        exit(0);
      }

      print_client_certification(ssl);

      read_write_server(ssl,s);//read and write into ssl

      //graceful close at braches at read_write_server
      return 0;
    }
  }

  //shouldnt_go_here:
  destroy_ctx(ctx);
  close(sock);
  return 1;

}

//------------------------------------------------------------------Setup TCP------------------------------------------------------------------
int setup_tcp(int port){
  int sock;
  struct sockaddr_in sin; //serv_addr in example
  int val=1;


  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  //setup sin
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }

  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  }
  
  return sock;

}


//---------------------------------------------------------------------Print Client Certification--------------------------------------------------
void print_client_certification(ssl)
  SSL *ssl;
{
  X509 *peer;
  char peer_CN[256];
  char peer_email[256];

  //berr_exit("Certificate doesn’t verify"); //unsure about here
  //berr_exit(FMT_ACCEPT_ERR);

 /*Check the cert chain. The chain length
42 is automatically checked by OpenSSL when
43 we set the verify depth in the ctx */

 //extract certificate
 peer=SSL_get_peer_certificate(ssl);
 if((peer == NULL) || (SSL_get_verify_result(ssl)!=X509_V_OK)){
    printf(FMT_ACCEPT_ERR);
    ERR_print_errors_fp(stdout); 
    return;
  }

 //Get common name
 X509_NAME_get_text_by_NID (X509_get_subject_name(peer),NID_commonName, peer_CN, 256);

 //Get client email
 X509_NAME_get_text_by_NID (X509_get_subject_name(peer),NID_pkcs9_emailAddress, peer_email, 256);

/* Unure if checks needed here
   if(strcasecmp(peer_CN,host))
   err_exit
   ("Common name doesn’t match host name");
*/

  //Print it out and return
  printf(FMT_CLIENT_INFO, peer_CN, peer_email);
 
 }

 

//-----------------------------------------------------------Read Write Server--------------------------------------------------------------------------
void read_write_server(SSL *ssl, int s){
  int len;
  char buf[256];
  char *answer = "42";

  //read from SSL connection
    int r;
    r = SSL_read(ssl,buf,256);
    switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          len=r;
          break;
        case SSL_ERROR_ZERO_RETURN:
          goto shutdown;
        case SSL_ERROR_SYSCALL:
          printf(FMT_INCOMPLETE_CLOSE);
          goto done;
        default:
          printf("SSL read problem");
    }

    //write to ssl connection
    buf[r] = '\0';
    
    printf(FMT_OUTPUT, buf, answer);
    r = SSL_write(ssl,answer,strlen(answer));
    switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
            if(strlen(answer)!=r)
                printf("Incomplete write!");
            break;
        case SSL_ERROR_ZERO_RETURN:
            goto shutdown;
        case SSL_ERROR_SYSCALL:
            printf(FMT_INCOMPLETE_CLOSE);
            goto done;
        default:
            printf("SSL write problem");
    }

    shutdown:
    r = SSL_shutdown(ssl);
    //printf("shutdown_all_server: value of r is %d\n", r);
    
    if(!r){   
      /*If we called SSL_shutdown() first then
      we always get return value of ’0’. In
      this case, try again, but first send a
      TCP FIN to trigger the other side’s
      close_notify*/
      shutdown(s,1);
      r=SSL_shutdown(ssl);
    }

    switch(r)
    {
        case 1:
            break; /* Success */
        case 0:
        case -1:
        default:
            printf("Shutdown failed");
            //ber exit
    }

    done:
    SSL_free(ssl);
    close(s);
    return;
}

