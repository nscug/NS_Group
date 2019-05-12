#ifndef TOOL_H_INCLUDED
#define TOOL_H_INCLUDED

struct IP_PORT_ID{
    char AS_IP[16];
    int AS_PORT;
    char TGS_ID[20];
    char TGS_IP[16];
    int TGS_PORT;
    char V_ID[20];
    char V_IP[16];
    int V_PORT;

};

struct Certificate{
    char ID[6];
    char Pk_n[1024];
    char Pk_e[56];
    char signature[32];
};

void get_local_ip(char* ip);

void gen_TS(char* TS);

void load_info(struct IP_PORT_ID* info);

void load_certificate(struct Certificate* info);

void RSA_encryption(char* sourceFilePath,char* keyFilePath,char* resultFilePath);

void RSA_decryption(char* sourceFilePath,char* keyFilePath,char* resultFilePath);

void DES_encryption(unsigned char*M,long long length,unsigned char*key,unsigned char*C);

void DES_decryption(unsigned char*C,long long length,unsigned char*key,unsigned char*M);

int connect_server(char *host, int port);

int SigVer(char* data,int length,char* certificate,char* signature);

void Log(char* data,int length,int type);

void MD5to56(unsigned char* source,unsigned char* result);

int RSA_authentic(char* data, char* signature, char* keyFilePath);

#endif // TOOL_H_INCLUDED
