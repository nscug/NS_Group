#ifndef TOOL_H_INCLUDED
#define TOOL_H_INCLUDED

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <pwd.h>
#include <netinet/in.h>
#include <time.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <mysql.h>

typedef struct
{
	char type[5];
	char ID_c[20];
	char ID_v[20];
	char ID_tgs[20];
	char AD_c[16];
	char Key_c_tgs[7];
	char Key_c_v[7];
	char Publickey_n[1024];
	char Publickey_e[8];
	char Timestamp[64];
	char Signature[16];
	char Lifetime[8];
	char Ticket[1024];
	char Sessionkey[7];
	char Data[1024];
}INFO;

void Gen_package(INFO* info, char* package);

void Analysis(char* data, long long length, INFO* info);

void gen_TS(char* TS);

void RSA_encryption(char* sourceFilePath,char* keyFilePath,char* resultFilePath);

void RSA_decryption(char* sourceFilePath,char* keyFilePath,char* resultFilePath);

void DES_encryption(unsigned char*M,long long length,unsigned char*key,unsigned char*C);

void DES_decryption(unsigned char*C,long long length,unsigned char*key,unsigned char*M);

void Respond_As(char* data,int socket,char* IP);

void gen_ticket(INFO* info,char* data);

int findDB(char* tableName,char* CMD,char* rFilePath);

void Log(char* data,int length,int type);

//void Gen_ticket_TGS(INFO* info,
#endif // TOOL_H_INCLUDED
