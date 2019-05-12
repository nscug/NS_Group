#include "server.h"
#include "tool.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <netinet/in.h>
#include <time.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <sys/wait.h>
int create_socket(int port)
{
  int sock;
  int reuse = 1;

  struct sockaddr_in server_address;
  if((sock = socket(AF_INET, SOCK_STREAM, 0))== -1)
   {
      perror("creating socket failed!");
      exit(-1);
    }
 
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));//reuse addr and port

  memset(&server_address,0,sizeof(server_address));
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(port);
  server_address.sin_addr.s_addr = htonl(INADDR_ANY);
  
  if(bind(sock,(struct sockaddr*) &server_address, sizeof(server_address)) < 0)
  {
    printf("Cannot bind socket to address\n");
    exit(-1);
  }

  listen(sock,5);
  return sock;
}


void my_wait(int signum){
  int state;
  wait( &state );
}

void server(int port)
{
  struct sockaddr_in client_address;
  socklen_t len = sizeof(client_address);
  int connection, pid, bytes_read;
  int sock = create_socket(port);
  while(1)
  {
    connection = accept(sock, (struct sockaddr*) &client_address,&len);
    char buffer[4096];
    signal(SIGCHLD,my_wait);
    pid = fork();
    
    memset(buffer,0,4096);

    if(pid<0)
    {
      printf("Cannot create child process.");
      exit(-1);
    }

    if(pid==0)
    {
      while (bytes_read = read(connection,buffer,4096))//recv cmd from client
      {
        unsigned char sessionKey[7];

        if( bytes_read<=4096 && bytes_read>0)
        {
        
          buffer[bytes_read-1] = '\0';
          //printf("%s\n",buffer);
		  char IP[20];
		  sprintf(IP,"%s",inet_ntoa(client_address.sin_addr));
          Respond_V(buffer,connection,IP,sessionKey);
          memset(buffer,0,4096);
        }
        else
        {
          printf("server:read\n");
        }
      }
      printf("Client disconnected.\n");
      exit(0);
    }
    else
    {
      sleep(1);
      printf("closing... :(\n");
      close(connection);
    }
  }
}




