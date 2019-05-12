#include <stdio.h>

void RSA_decryption(char* sourceFilePath,char* keyFilePath,char* resultFilePath){
    char cmd[256];
    sprintf(cmd,"python3 decryption.py %s %s %s\0",sourceFilePath,keyFilePath,resultFilePath);
	//printf("%s\n",cmd);
    FILE* file =popen(cmd,"r");
    pclose(file);
}

int main(){
	
	RSA_decryption("ticketTmp.txt","TGS_Sk.txt","result.txt");
	return 0;
}