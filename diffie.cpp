/* A server and client exercising Diffie-Hellman Key Exchange
   The port number and server address are passed as arguments
   
   Author - Sam Halligan
*/
     
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <iostream>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#include "big.h"
#include <ctime>

using namespace std;


#ifndef MR_NOFULLWIDTH
Miracl precision(50,0);
#else 
Miracl precision(50,MAXBASE);
#endif

void error(string msg)
{
     cout << msg << endl;
     exit(1);
}

void hostServer(int portno)
{
     int sockfd, newsockfd, clilen;
     struct sockaddr_in serv_addr, cli_addr;

     sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) 
        error("ERROR opening socket");
     memset((char *) &serv_addr, 0, sizeof(serv_addr));
     serv_addr.sin_family = AF_INET;
     serv_addr.sin_addr.s_addr = INADDR_ANY;
     serv_addr.sin_port = htons(portno);
     if (bind(sockfd, (struct sockaddr *) &serv_addr,
              sizeof(serv_addr)) < 0) 
              error("ERROR on binding");
     
     listen(sockfd,5);
     clilen = sizeof(cli_addr);
     newsockfd = accept(sockfd, 
                 (struct sockaddr *) &cli_addr, 
                 (socklen_t *) &clilen);
     if (newsockfd < 0) 
          error("ERROR on accept");
	 else cout << "Connection established\n" << endl;

     // KEY CALCULATION 
     Big a,p,q,r,pa,pb,key;
     miracl *mip=&precision;
	 time_t seed;
	 time(&seed);
     irand((long)seed);   //Random number so we generate a different key each run

     cout << "CA 304 - Assignment 1 - Diffie Hellman\n" << endl;
	 cout << "\nBe patient, this might take a while...\n" << endl;

     //Get p
     p=rand(1024,2);     
     p=nextsafeprime(0,0,p); // Method from Big.cpp
     
	 char buffer[310];
     memset(buffer, 0, 310);
     
     //Convert Big to char array to send to client
     mip -> IOBASE=10;
     buffer << p;
     
     cout << "\np = ";
     cout << buffer << endl;
     
     cout << "\nSend p" << endl;
     
     //Send p to client
	 int n;
     n = write(newsockfd,buffer,strlen(buffer));
     
     if (n < 0)
          error("ERROR writing to socket");
     
     /* Calculate primitive root */     
     r=2;
     
     while ((pow(r,((p-1)/2),p) == 1))
     {
          r+=1;
     }
     
     cout << "\nPrimitive root = ";
     cout << r << endl;
	
     
     cout << "\nSend primitive root" << endl;
     
     // Fill with zero's
     memset(buffer, 0, 310);
     
     //Convert Big to char array[310]
     mip -> IOBASE=10;
     buffer << r;
     
     /* Send p */
     n = write(newsockfd,buffer,strlen(buffer));
     
     if (n < 0)
          error("ERROR writing to socket");
     
     cout << "\nCalcualte a and pa" << endl;
     a=rand(512,2);
     
     cout << "\na = ";
     cout << a << endl;

     pa=pow(r,a,p);             // pa = r^a mod p
     
     cout << "\npa = ";
     cout << pa << endl;
     
     cout << "\nSend pa" << endl;
     
     /* Clear buffer */
     memset(buffer, 0, 310);
     
     /* Convert Big to char array[310] */
     mip -> IOBASE=10;
     buffer << pa;
     
     //Send message
     n = write(newsockfd,buffer,strlen(buffer));
     
     if (n < 0)
          error("ERROR writing to socket");    
     
     cout << "\nReceive pb" << endl;
     
     /* Clear buffer */
     memset(buffer, 0, 310);
     
     /* Receive pb */
     n = read(newsockfd,buffer,309);
     
     if (n < 0) 
          error("ERROR on accept");
          
     /* Convert char array[310] to Big */
     mip->IOBASE=10;
     pb=buffer;
     
     cout << "\npb = ";
     cout << pb << endl;
     
     cout << "\nCalculate Key=" << endl;
     key=pow(pb,a,p);
     cout << key << endl;

	 close(sockfd);
     return; 
}

void client(hostent* server, int portno)
{
     int sockfd, n;
     sockaddr_in serv_addr;

     char buffer[310];
    
     sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) 
          error("ERROR opening socket");
        
     memset((char *) &serv_addr, 0, sizeof(serv_addr));
     serv_addr.sin_family = AF_INET;
     bcopy((char *)server->h_addr,
          (char *)&serv_addr.sin_addr.s_addr,
          server->h_length);
     serv_addr.sin_port = htons(portno);
     if (connect(sockfd,(const sockaddr*)&serv_addr,sizeof(serv_addr)) < 0) 
          error("ERROR connecting");
	 else cout << "Connection established\n" << endl;
          
     /* KEY CALCULATION */
     Big b,p,r,pa,pb,key;
     miracl *mip=&precision;
	 
	 time_t seed;
     time(&seed);
     irand((long)seed);   /* change parameter for different values */
     
     cout << "CA 304 - Assignment 1 - Diffie Hellman\n" << endl;
	 cout << "\nBe patient, this might take a while...\n" << endl;
     
     /* Clear buffer */
     memset(buffer, 0, 310);
     
     /* Receive p */
     n = read(sockfd,buffer,310);
     
     if (n < 0) 
          error("ERROR on accept");
     
     /* Convert char array[310] to Big */     
     mip->IOBASE=10;
     p=buffer;
	 
	
	 cout << "\nReceived p" << endl;
     cout << "\np = ";
     cout << p << endl;
     
     /* Clear buffer */
     memset(buffer, 0, 310);
     
     /* Receive primitive root */
     n = read(sockfd,buffer,310);
     
     if (n < 0)
          error("ERROR on accept");
     
     /* Convert char array[310] to Big */          
     mip->IOBASE=10;
     r=buffer;
     
	 cout << "\nReceived primitive root" << endl;
     cout << "\nPrimitive root = ";
     cout << r << endl;

     cout << "\nCalculate b and pb" << endl;        
     b=rand(512,2);
     
     cout << "\nb = ";
     cout << b << endl;
     
     pb=pow(r,b,p);             // pb = r^b mod p
     
     cout << "\npb = ";
     cout << pb << endl;
     
     cout << "\nReceived pa" << endl;
     
     /* Clear buffer */
     memset(buffer, 0, 310);
     
     /* Receive message */
     n = read(sockfd,buffer,310);
     
     if (n < 0) 
          error("ERROR on accept");

     /* Convert char array[310] to Big */          
     mip->IOBASE=10;
     pa=buffer;
     
     cout << "\npa = ";
     cout << pa << endl;
          
     cout << "\nSent pb" << endl;
     
     /* Clear buffer */
     memset(buffer, 0, 310);
     
     /* Convert Big to char array[310] */
     mip -> IOBASE=10;
     buffer << pb;     
     
     /* Send message */
     n = write(sockfd,buffer,strlen(buffer));
     
     if (n < 0)
          error("ERROR writing to socket");
    
     cout << "\nCalculate Key=" << endl;
     key=pow(pa,b,p);
     cout << key << endl;
     
	 close(sockfd);
     return;
}

int main(int argc, char *argv[])
{
     int portno;
     hostent *server;
     
     if (argc < 2)//Check if enough arguments are supplied
     {
          fprintf(stderr, "ERROR: state whether to use server(S) or client(C)\n");
          exit(0);
     }

     if (argv[1][0] == 'S')//Server being started
     	if (argc < 3)
          {
               fprintf(stderr,"usage %s S port\n", argv[0]);
               exit(1);
          }
     
          portno = atoi(argv[2]);//String to int
          hostServer(portno);
     
     if (argv[1][0] == 'C')//Client being started
     	if (argc < 4)
          {
               fprintf(stderr,"usage %s C hostname port\n", argv[0]);
               exit(1);
          }
          
          portno = atoi(argv[3]);
          server = gethostbyname(argv[2]);    
          client(server,portno);
}
