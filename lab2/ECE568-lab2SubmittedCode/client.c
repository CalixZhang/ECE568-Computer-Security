//Good reference - http://www.thegeekstuff.com/2011/12/c-socket-programming/
// http://www.cs.odu.edu/~cs772/fall04/lectures/ssl_programming.html

/*
  AF_INET is an address family that is used to designate the type of addresses that your socket can communicate with 
  (in this case, Internet Protocol v4 addresses). When you create a socket, you have to specify its address family, 
  and then you can only use addresses of that type with the socket. The Linux kernel, for example, 
  supports 29 other address families such as UNIX (AF_UNIX) sockets and IPX (AF_IPX), and also communications with IRDA 
  and Bluetooth (AF_IRDA and AF_BLUETOOTH, but it is doubtful you'll use these at such a low level).
  For the most part, sticking with AF_INET for socket programming over a network is the safest option. 
  There is also AF_INET6 for Internet Protocol v6 addresses.
*/


/*
  File Descriptor - In simple words, when you open a file, the operating system creates an entry to represent that file and store the information 
  about that opened file. So if there are 100 files opened in your OS then there will be 100 entries in OS (somewhere in kernel). 
  These entries are represented by integers like (...100, 101, 102....). This entry number is the file descriptor. 
  So it is just an integer number that uniquely represents an opened file in operating system. If your process opens 10 files,
  then your Process table will have 10 entries for file descriptors.
  Similarly when you open a network socket, it is also represented by an integer and it is called Socket Descriptor.
*/


#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//my header file
#include "sslfunctions.h"

#define HOST "localhost"
#define PORT 8765 //use this port my default, or else use the one thats passed in as arguments

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

//my defined functions
int tcp_connect(char* host, int port);
int check_certificate(SSL *ssl);
void read_write_client(SSL *ssl, char * secret);


//my defined constants
#define CN_SERVER "Bob's Server"
#define EMAIL "ece568bob@ecf.utoronto.ca"
#define CLIENTKEYFILE "alice.pem"
#define CLIENTPASSWORD "password"


/*---------------------------------------------------------------Main Function------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
  int sock, port=PORT;
  char *host=HOST;
    
  char *secret = "What's the question?";
  
  /*Parse command line arguments*/
  switch(argc){
    case 1: //if 1 arg, which is just ./client then use port 8765
      break;
    case 3: //if 3 args, use hostname entered and portnumber given
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
    fprintf(stderr,"invalid port number");
    exit(0);
      }
      break;
    default:  //if random number of arguents, then print this and exit
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }


  //Initialization of ssl stuff
  SSL_CTX *ctx; 
  SSL *ssl; 
  BIO *sbio;  

  //Context Initializaton: load our own keys
  ctx = initialize_ctx(CLIENTKEYFILE, CLIENTPASSWORD);
  
  //Set CTX options to communicate with servers using SSLv3 or TLSv1 by only removing SSLv2
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
  
  //set cipher list to SHA1
  SSL_CTX_set_cipher_list(ctx, "SHA1");
  
  //Creates a tcp connection
  sock = tcp_connect(host,port);

  //Create and set up a new SSL structure to hold the SSL connection. Make a BIO object using the socket and attch the SSL obkect to the BIO
  ssl = SSL_new(ctx);
  sbio = BIO_new_socket(sock,BIO_NOCLOSE); //read and write socket BIO
  SSL_set_bio(ssl,sbio,sbio);
  
  //Initiate the SSL handshake with a server
  //printf("Initiate SSL handshake\n");
    int r = 0;
    if((r = SSL_connect(ssl)) <=0) {
        //printf("SSL connect error, errno: %d\n", SSL_get_error(ssl, r));
        printf(FMT_CONNECT_ERR);
        ERR_print_errors_fp(stdout);  //unsure
        goto finish;
    }
    
    //SSL connection initiated. Now verify certificate
    //printf("Checking the server's certificate\n");
    /* Check server's certificate */
    if (check_certificate(ssl) == 0) {
      //If certificatse ok, continue.

      /* make our read and write request */
      read_write_client(ssl, secret);
    }
    
    finish:
    destroy_ctx(ctx);
    close(sock);
    return 1;
}



/*-------------------------------------------------------------TCP Connection----------------------------------------------------------------*/
int tcp_connect(char* host, int port){
  int sock;
  struct hostent *host_entry;
  struct sockaddr_in addr;

  /*get ip address of the host*/
  host_entry = gethostbyname(host);  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  /*  
    Filling in addr variable which is of type sockaddr_in. struct sockaddr_in is the structure used 
    with IPv4 addresses (e.g. "192.0.2.10"). It holds an address family (AF_INET), 
    a port in sin_port, and an IPv4 address in sin_addr.
  */
  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  /* The htons() function converts the unsigned short integer hostshort 
  from host byte order to network byte order. */
  addr.sin_port=htons(port); 


  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)  //creates socket
    perror("Error: Couldn't create socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)  //connects
    perror("Error: Couldn't connect to socket");

  return sock;

}


/*-------------------------------------------------------------Check Certificate----------------------------------------------------------------*/

int check_certificate(SSL *ssl){

  //Initialize X509 certificate format and utilities 
  X509 *peer;
  char peer_CN[256];
  char peer_email[256];
  char peer_certificate_issuer[256];
  
  //Obtain the X509 certificate for the peer
  peer = SSL_get_peer_certificate(ssl);
  
  //Verify the certificate that was obtained
  if ((peer == NULL) || (SSL_get_verify_result(ssl) != X509_V_OK)){
    printf(FMT_NO_VERIFY);
    return -1;
  }
  
  //Examine name structures to obatain peer's Common Name, email address and certificate issuer
  X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
  X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_email, 256);  
  X509_NAME_get_text_by_NID (X509_get_issuer_name(peer), NID_commonName, peer_certificate_issuer, 256);
  
  //Verify server's common name
  if (strcasecmp(peer_CN,CN_SERVER)) {
        printf(FMT_CN_MISMATCH);        
        return -1;        
  }
    
  //Verify server's email address
  if (strcasecmp(peer_email, EMAIL)) {
        printf(FMT_EMAIL_MISMATCH);
        return -1;
    }
    
  //Server's Common Name and Email Address matched
  printf(FMT_SERVER_INFO, peer_CN, peer_email, peer_certificate_issuer);
  return 0;
  
}


/*-------------------------------------------------------------Request for a connection----------------------------------------------------------------*/
void read_write_client(SSL *ssl, char * secret){

  char buf[256];
  int secret_length = strlen(secret);
  int length_read;


  //Write the secret to ssl connection
  //printf("SSL_WRITE %s\n", secret);
  int r = SSL_write(ssl,secret,secret_length);
  
  //If an error occurred, determine what caused it. r will have value whats returned from SSL_write
    switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
            if(secret_length!=r)
                printf("Incomplete write!");
            break;
        case SSL_ERROR_ZERO_RETURN:
            goto shutdown;
        case SSL_ERROR_SYSCALL:
            printf(FMT_INCORRECT_CLOSE);
            goto done;
        default:
            printf("SSL write problem");
    }
    
    /*Read from the ssl connection */
    while(1){
        r=SSL_read(ssl,buf,256);
        
    //If an error occurred, determine what caused it
        switch(SSL_get_error(ssl,r)){
            case SSL_ERROR_NONE:
                length_read=r;
                break;
            case SSL_ERROR_ZERO_RETURN:
                goto shutdown;
            case SSL_ERROR_SYSCALL:
                printf(FMT_INCORRECT_CLOSE);
                goto done;
            default:
                printf("SSL read problem");
        }
        buf[length_read]='\0';
        printf(FMT_OUTPUT, secret, buf);
    }
    
    shutdown:
    r=SSL_shutdown(ssl);
    switch(r){
        case 1:
            break; /* Success */
        case 0:
        case -1:
        default:
            printf("Shutdown failed");
    }
    
    done:
    SSL_free(ssl);
    return;

}

