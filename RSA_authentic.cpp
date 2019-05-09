#include <stdio.h>
#include <string>
#include //RSA加密函数文件名
#include //MD5

//sourceFilePath="a.txt"
//keyFilePath=
//resultFilePath="result.txt"
int RAS_authentic(char* data,const char* signature,const char* sourceFilePath,const char* keyFilePath)
{
	FILE *fp = NULL;
	fp = fopen(sourceFilePath, "w+");
	fputs(signature,fp);
	fclose(fp);
	char b[16] ;
	char resultFilePath[]= "result.txt";
	RSA_decryption(sourceFilePath, keyFilePath, resultFilePath);
	MD5IN(data,b);//调用MD5函数
	FILE *fp = NULL;
	fp = fopen(resultFilePath ,"r");
	char result[50];
	fgets(result, 50, (FILE*)fp);
	fclose(fp);
	if (strcmp(b, result) == 0) {
		return 0;
	}
	else {
		return -1;
	}
}
