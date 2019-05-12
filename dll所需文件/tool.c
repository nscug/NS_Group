#include "tool.h"
#include "des.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <Winsock2.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


int SigVer(char* data,int length,char* certificate,char* signature){
    //log RSA 验证：data\n签名：signature
    FILE* file =fopen("VerTmp.txt","w");
    fwrite(data,length,1,file);
    fclose(file);
    RSA_decryption("VerTmp.txt",certificate,"VerResultTmp.txt");
    file =fopen("VerResultTmp.txt","r");
    char result[1024],tmp[32];
    if(file){
        fscanf(file,"%s",result);
        //md5
        //log 验证hash值
    }
    fclose(file);
    if(strcmp(signature,tmp)==0){
        return 1;
    }
    else{
        return 0;
    }

}

void load_info(struct IP_PORT_ID* info){
    FILE* file =fopen("T:\\学习\\学习大三下\\Project1\\Debug\\AS_TGS_V_IP_PORT.txt","r");
    if(file){
        fscanf(file,"%s%d%s%s%d%s%s%d",info->AS_IP,&info->AS_PORT,info->TGS_ID,
               info->TGS_IP,&info->TGS_PORT,info->V_ID,info->V_IP,&info->V_PORT);
    }
    fclose(file);
}

void load_certificate(struct Certificate* info){
    FILE* file =fopen("T:\\学习\\学习大三下\\Project2\\Debug\\certificate.txt","r");
    if(file){
        fscanf(file,"%s\n%s\n%s",info->ID,info->Pk_n,info->Pk_e);
    }
    fclose(file);
}

void get_local_ip(char* ip){
    WORD v = MAKEWORD(1, 1);
	WSADATA wsaData;
	WSAStartup(v, &wsaData); // 加载套接字库

	struct hostent *phostinfo = gethostbyname("");
	char *p = inet_ntoa (* ((struct in_addr *)(*phostinfo->h_addr_list)) );
	strcpy(ip, p);
	WSACleanup();
}

void gen_TS(char* TS){
    time_t now =time(NULL);
    struct tm* T =localtime(&now);
	strcpy(TS,asctime(T));
}

void RSA_encryption(char* sourceFilePath,char* keyFilePath,char* resultFilePath){
    char cmd[256];
    sprintf(cmd,"python encryption.py %s %s %s\0",sourceFilePath,keyFilePath,resultFilePath);
	//printf("%s\n",cmd);
    FILE* file =_popen(cmd,"r");
    _pclose(file);
}


void RSA_decryption(char* sourceFilePath,char* keyFilePath,char* resultFilePath){
    char cmd[256];
    sprintf(cmd,"python decryption.py %s %s %s\0",sourceFilePath,keyFilePath,resultFilePath);
	//printf("%s\n",cmd);
    FILE* file =_popen(cmd,"r");
    _pclose(file);
}

void DES_encryption(unsigned char*M,long long length,unsigned char*key,unsigned char*C){
    unsigned char extend_key[56];
    myExtend1_8(key,extend_key);

    long long index =0;
    while(length >0){
        unsigned char _M[8]="\0",extend_M[64],_C[8],extend_C[64];

        memcpy(_M,M+index,8);
        myExtend1_8(_M,extend_M);

        encryption(extend_M,extend_key,extend_C);

        /*for(int i =0;i <64;i++){
            printf("%d ",extend_C[i]);
        }
        printf("\n");*/

        myReduce8_1(extend_C,_C);

        memcpy(C+index,_C,8);
        index+=8;
        length-=8;
    }
}

void DES_decryption(unsigned char*C,long long length,unsigned char*key,unsigned char*M){
    long long  index =0;
	unsigned char _key[] = "0000000";
	for (int i = 0; i < 7; i++) {
		_key[i] = key[i];
	}
    while(length >0){
        unsigned char _M[8],extend_M[64],_C[8],extend_C[64];

        memcpy(_C,C+index,8);
        myExtend1_8(_C,extend_C);

        unsigned char extend_key[64];
        myExtend1_8(_key,extend_key);
        /*for(int i =0;i <64;i++){
            printf("%d",extend_key[i]);
        }
        printf("\n");*/

        decryption(extend_C,extend_key,extend_M);

        myReduce8_1(extend_M,_M);


        memcpy(M+index,_M,8);
        index+=8;
        length-=8;
    }
}

int _socket_connect(char *host,int port){
    struct sockaddr_in address;
    int sock, opvalue;
    //int len;

    memset(&address, 0, sizeof(address));

    //if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 ||setsockopt(sock, IPPROTO_IP, IP_TOS, &opvalue, len) < 0)
        //return -1;

    WORD request;
    WSADATA wsdata;
    request =MAKEWORD(1,1);
    if(WSAStartup(request,&wsdata) != 0){
        return -1;
    }
    if ((sock =socket(AF_INET,SOCK_STREAM,0)) <0){
        return -1;
    }
    //struct timeval timeout = {15, 0};//set time out
    opvalue = 500;
    //len = sizeof(opvalue);
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &opvalue, sizeof(opvalue));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &opvalue, sizeof(opvalue));

    address.sin_family = AF_INET;
    address.sin_port = htons(port);

    struct hostent* server = gethostbyname(host);
    if (!server)
        return -1;

    memcpy(&address.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(sock, (struct sockaddr*) &address, sizeof(address)) == -1){
        return -1;
    }

    return sock;
}

int connect_server(char* host,int port){
    int       ctrl_sock;

    ctrl_sock = _socket_connect(host, port);
    if (ctrl_sock == -1)
    {
        return -13;
    }
    return ctrl_sock;
}


void Log(char* data,int length,int type){
	FILE *file = fopen("log.txt","a");
	if(file){
		//flock(file->_fileno,LOCK_EX);
		char TS[64];
		gen_TS(TS);
		fprintf(file,"%s",TS);
		if(type == 1){
			for(int i =0;i <length;i++){
				fprintf(file,"%c",data[i]);
			}
		}
		else{
			for(int i =0;i <length;i++){
				fprintf(file,"%02x",data[i]);
			}
		}
		fprintf(file,"%s","\n");
		//flock(file->_fileno,LOCK_UN);
		fclose(file);
	}
}

void MD5to56(unsigned char* ori,unsigned char* result){
    memset(result,0,7);
    char a[4], b[4], c[4], d[4];
	for (int i = 0; i < 16; i++) {
		if (i < 4) {
			a[i % 4] = ori[i];
			continue;
		}
		else if (i < 8) {
			b[i % 4] = ori[i];
			continue;
		}
		else if (i < 12) {
			c[i % 4] = ori[i];
			continue;
		}
		else {
			d[i % 4] = ori[i];
			continue;
		}
	}
	for (int i = 0, j = 0; i < 7 ; i++, j++) {
		if (j < 4) {
			int temp = result[i];
			temp+= a[j];
			temp %= 127;
			result[i] = temp;
		}
		if ((j - 1 + 7) % 7 < 4) {
			int temp = result[i];
			temp += a[(j - 1 + 7) % 7];
			temp %= 127;
			result[i] = temp;
		}
		if ((j - 2 + 7) % 7 < 4) {
			int temp = result[i];
			temp += a[(j - 2 + 7) % 7];
			temp %= 127;
			result[i] = temp;
		}
		if ((j - 3 + 7) % 7 < 4) {
			int temp = result[i];
			temp += a[(j - 3 + 7) % 7];
			temp %= 127;
			result[i] = temp;
		}
	}
	for (int i = 0; i < 7; i++) {
		int m = result[i];
		if (result[i] < 33)result[i] += 33;
	}
}

int RSA_authentic(char* data, char* signature, char* keyFilePath)
{
	FILE *file = NULL;
	file = fopen("tmp.txt", "w");
	fprintf(file, "%s", signature);
	fclose(file);
	unsigned char d[] = "0000000000000000", d2[] = "00000000000000000000000000000000";
	MD5IN(data, d);
	for (int i = 0; i < 16; i++) {
		sprintf(d2 + i * 2, "%02x", d[i]);
	}
	char resultFilePath[] = "result.txt";
	RSA_decryption("tmp.txt", keyFilePath, resultFilePath);
	//MD5IN((unsigned char*)data,(unsigned char*)b);//调用MD5函数
	file = fopen(resultFilePath, "r");
	char result[33];
	fgets(result, 33, (FILE*)file);
	fclose(file);
	//Log(b1,32,1);
	if (strcmp(d2, result) == 0) {
		/*char cmd[256];
		sprintf(cmd,"rm %s %s","tmp.txt","result.txt");
		FILE* file =popen(cmd,"r");
		pclose(file);*/
		return 0;
	}
	else {
		/*char cmd[256];
		sprintf(cmd,"rm %s %s","tmp.txt","result.txt");
		FILE* file =popen(cmd,"r");
		pclose(file);*/
		return -1;
	}
}



