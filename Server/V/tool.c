#include "tool.h"
#include "des.h"
#include "MD5.h"

void i_c4(int i,char *pp) {
	int j;
	int m = 1;
	char p[] = "0000";
	while (i > 0) {
		j = i % 10;
		p[4 - m] = '0' + j;
		m++;
		i = i / 10;
	}
	for (int ii = m; ii <= 4; ii++) {
		p[4 - ii] = '0';
	}
	strcpy(pp,p);
}

int c4_i(char* pp) {
	int a = 0;
	if (pp[0] == '0') {
		if (pp[1] == '0') {
			if (pp[2] == '0') {
				a = pp[3] - 48;
			}
			else {
				a = 10 * (pp[2]-48) + (pp[3]-48);
			}
		}
		else {
			a = 100 * (pp[1]-48) + 10 * (pp[2]-48) + (pp[3]-48);
		}
	}
	else {
		a = 1000 * (pp[0]-48) + 100 * (pp[1]-48) + 10 * (pp[2]-48) + (pp[3]-48);
	}
	return a;
}

void cpy(INFO *info, int i, const char* p) {
	if (i == 0) {
		strcpy(info->type, p);
	}
	else if (i == 4) {
		strcpy(info->ID_c, p);
	}
	else if (i == 8) {
		strcpy(info->ID_v, p);
	}
	else if (i == 12) {
		strcpy(info->ID_tgs, p);
	}
	else if (i == 16) {
		strcpy(info->AD_c, p);
	}
	else if (i == 20) {
		strcpy(info->Key_c_tgs, p);
	}
	else if (i == 24) {
		strcpy(info->Key_c_v, p);
	}
	else if (i == 28) {
		strcpy(info->Publickey_n, p);
	}
	else if (i == 32) {
		strcpy(info->Publickey_e, p);
	}
	else if (i == 36) {
		strcpy(info->Timestamp, p);
	}
	else if (i == 40) {
		strcpy(info->Signature, p);
	}
	else if (i == 44) {
		strcpy(info->Lifetime, p);
	}
	else if (i == 48) {
		strcpy(info->Ticket, p);
	}
	else if (i == 52) {
		strcpy(info->Sessionkey, p);
	}
	else if (i == 56) {
		strcpy(info->Data, p);
	}
}

void gen_TS(char* TS){
    time_t now =time(NULL);
    struct tm* T =localtime(&now);
	strcpy(TS,asctime(T));
    /*char year[4],mon[2],day[2],hour[2],min[2],sec[2];
    itoa(T->tm_year+1900,year,10);
    strcat(TS,year);
    strcat(TS,".");
    itoa(T->tm_mon,mon,10);
    strcat(TS,mon);
    strcat(TS,".");
    itoa(T->tm_mday,day,10);
    strcat(TS,day);
    strcat(TS,":");
    itoa(T->tm_hour,hour,10);
    strcat(TS,hour);
    strcat(TS,":");
    itoa(T->tm_min,min,10);
    strcat(TS,min);
    strcat(TS,":");
    itoa(T->tm_sec,sec,10);
    strcat(TS,sec);*/
}

void Log(char* data,int length,int type){
	FILE *file = fopen("log.txt","a");
	if(file){
		flock(file->_fileno,LOCK_EX);
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
		flock(file->_fileno,LOCK_UN);
		fclose(file);
	}
}

void Analysis(char* data, long long length,INFO* info) {
	char p[] = "0000";
	char q[] = "0000";
	int b1 = 0;
	int b2 = 0;
	int j = 0;
	p[0] =data[80];p[1]=data[81];p[2]=data[82];p[3] =data[83];
	cpy(info,0,p);
	for (int i = 4; i < 60; i = i + 4) {
		p[0] = data[i];
		p[1] = data[i + 1];
		p[2] = data[i + 2];
		p[3] = data[i + 3];
		if (strcmp(p, "00-1") == 0) {
			//cpy(info, i, "");
			continue;
		}
		else {
			j = i + 4;
			int flag =0;
			while (j < 60) {
				q[0] = data[j];
				q[1] = data[j + 1];
				q[2] = data[j + 2];
				q[3] = data[j + 3];
				if (strcmp(q, "00-1") == 0) {
					j = j + 4;
					continue;
				}
				else {
                    if(i == 0)
                        b1 =0;
                    else
                        b1 = c4_i(p);
					b2 = c4_i(q);
					char pp[1024] = { 0 };
					for (int m = b1; m < b2; m++) {
						pp[m - b1] = data[m+80];
					}
					cpy(info, i, pp);
					flag =1;
					break;
				}
			}
            if(flag==0){
                b1 = c4_i(p);
                char pp[1024] = { 0 };
                for (int m = b1; m <= length; m++) {
                    pp[m - b1] = data[m+80];
                }
                cpy(info, i, pp);
            }
		}
	}
}

void Gen_package(INFO* info, char* package) {
	int i = 0;
	char* p = NULL;
	p = (char *)malloc(4016*sizeof(char));
	char *pp = NULL;
	pp = (char *)malloc(4*sizeof(char));

	//package =(char*)malloc(80*sizeof(char));

	if (strcmp(info->type, "") == 0) {
		strcpy(package, "00-1");
	}
	else {
		strcpy(package, info->type);
		strcpy(p, info->type);
	}

	if (strcmp(info->ID_c, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p);
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info->ID_c);
	}

	if (strcmp(info->ID_v, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p);
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info->ID_v);
	}

	if (strcmp(info->ID_tgs, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p);
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info->ID_tgs);
	}

	if (strcmp(info->AD_c, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p);
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info->AD_c);
	}

	if (strcmp(info->Key_c_tgs, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p);
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info->Key_c_tgs);
	}

	if (strcmp(info->Key_c_v, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p);
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info->Key_c_v);
	}

	if (strcmp(info->Publickey_n, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p);
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info->Publickey_n);
	}

	if (strcmp(info->Publickey_e, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p);
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info->Publickey_e);
	}

	if (strcmp(info->Timestamp, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p);
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info->Timestamp);
	}

	if (strcmp(info->Signature, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p);
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info->Signature);
	}

	if (strcmp(info->Lifetime, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p);
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info->Lifetime);
	}

	if (strcmp(info->Ticket, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p);
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info->Ticket);
	}

	if (strcmp(info->Sessionkey, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p);
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info->Sessionkey);
	}

	if (strcmp(info->Data, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p);
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info->Data);
	}

	strcat(package, "00000000000000000000");
	strcat(package, p);
	free(p);
	p = NULL;
	free(pp);
	pp = NULL;
}

void Concealment(char* filePath){
	FILE* file =fopen(filePath,"r");
	FILE* file1 =fopen("tmp.txt","w");
	int i =1;
	char info[64];
	while(fgets(info,64,file)!=NULL){
		if((i+1)%4 ==0){
			info[3] ='*';info[4] ='*';info[6] ='*';info[7] ='*';info[8] ='*';info[9] ='*';info[10] ='*';info[5] ='*';
		}
		//printf("%s",info);
		fwrite(info,1,strlen(info),file1);
		i++;
		memset(info,0,64);
	}
	fclose(file);
	fclose(file1);
	char cmd[256],cmd2[128];
	sprintf(cmd,"rm %s",filePath);
	file =popen(cmd,"r");
	pclose(file);
	sprintf(cmd2,"mv tmp.txt %s",filePath);
	file =popen(cmd2,"r");
	pclose(file);
}

void RSA_encryption(char* sourceFilePath,char* keyFilePath,char* resultFilePath){
    char cmd[256];
    sprintf(cmd,"python3 encryption.py %s %s %s\0",sourceFilePath,keyFilePath,resultFilePath);
	//printf("%s\n",cmd);
    FILE* file =popen(cmd,"r");
	//ssleep(2);
    pclose(file);
}

void RSA_decryption(char* sourceFilePath,char* keyFilePath,char* resultFilePath){
    char cmd[256];
    sprintf(cmd,"python3 decryption.py %s %s %s\0",sourceFilePath,keyFilePath,resultFilePath);
	//printf("%s\n",cmd);
    FILE* file =popen(cmd,"r");
    pclose(file);
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
    unsigned char extend_key[56];
    myExtend1_8(key,extend_key);

    long long  index =0;
    while(length >0){
        unsigned char _M[8],extend_M[64],_C[8],extend_C[64];

        memcpy(_C,C+index,8);
        myExtend1_8(_C,extend_C);

        decryption(extend_C,extend_key,extend_M);
		

        /*for(int i =0;i <64;i++){
            printf("%d",extend_key[i]);
        }
        printf("\n");*/

        myReduce8_1(extend_M,_M);
		

        memcpy(M+index,_M,8);
        index+=8;
        length-=8;
    }
}

int findDB(char* DBName,char* CMD,char* rFilePath){
	MYSQL mysql;
	MYSQL_RES *res;
	MYSQL_ROW row;
	int t,flag;
	mysql_init(&mysql);
	if(!mysql_real_connect(&mysql,"192.168.1.144","root","root",DBName,0,NULL,0)){
		//Log("DB Connect filed",strlen("DB Connect filed"),1);
		return -2;
	}
	else{
		flag =mysql_real_query(&mysql,CMD,(unsigned int)strlen(CMD));
		if(flag){
			//Log("DB Query filed",strlen("DB Query filed"),1);
			return -1;
		}
		else{
			res =mysql_store_result(&mysql);
			FILE* file =fopen(rFilePath,"w");
			while(row =mysql_fetch_row(res)){
				for(t =0;t <mysql_num_fields(res);t++){
					fprintf(file,"%s",row[t]);
					fprintf(file,"%s","\n");
				}
			}
			fclose(file);
		}
	}
	mysql_close(&mysql);
	return 0;
}
int ana_Ticket(INFO* info,char* keyFilePath){
	char key_c_v[10],ID_c[20],ID_v[20],TS[20],lifeTime[5];
	memset(key_c_v,0,10);memset(ID_c,0,20);memset(ID_v,0,20);memset(TS,0,20);memset(lifeTime,0,5);
	char log[128];
	char* ptr[5] ={key_c_v,ID_c,ID_v,TS,lifeTime};
	
	FILE* file =fopen("ticketTmp.txt","w");
	fprintf(file,"%s",info->Ticket);
	fclose(file);
	//Log("RSA decryption",strlen("RSA decryption"),1);
	//Log(info->Ticket,strlen(info->Ticket),1);
	RSA_decryption("ticketTmp.txt",keyFilePath,"result.txt");
	
	file =fopen("result.txt","r");
	fseek(file,0,SEEK_END);
	int size =ftell(file);
	rewind(file);
	memset(log,0,128);
	fread(log,1,size,file);
	//Log(log,strlen(log),1);
	char* p;
	p =strtok(log,";");
	int i=0;
	while(p){
		strcpy(ptr[i++],p);
		 p=strtok(NULL,";");
	}
	
	if(strcmp(ID_c,info->ID_c) != 0){
		return -1;
	}
	else{
		strcpy(info->Key_c_v,key_c_v);
	}
	
	char cmd[256];
	sprintf(cmd,"rm %s %s","ticketTmp.txt","result.txt");
	file =popen(cmd,"r");
	pclose(file);
	return 0;
	
}

int RAS_authentic(char* data,char* signature,char* keyFilePath)
{
	FILE *fp = NULL;
	fp = fopen("tmp.txt", "w+");
	fputs(signature,fp);
	fclose(fp);
	char b[16],b1[32];
	char resultFilePath[]= "result.txt";
	RSA_decryption("tmp.txt", keyFilePath, resultFilePath);
	MD5IN((unsigned char*)data,(unsigned char*)b);//调用MD5函数
	fp = fopen(resultFilePath ,"r");
	char result[32];
	fgets(result, 32, (FILE*)fp);
	fclose(fp);
	for(int i=0;i<16;i++){
            sprintf(b1+i*2,"%02x",b[i]);
    }
	//Log(b1,32,1);
	if (strcmp(b1, result) == 0){
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

void Respond_7(char* data,int socket,char* IP){
	INFO info ={""};
	Analysis(data,strlen(data),&info);
	if( ana_Ticket(&info,"Sk.txt") ==-1){
		char log[256];
		sprintf(log,"%s Illegal request",IP);
		//Log(log,strlen(log),1);
		char M[4096];
		strcpy(info.type,"0009");
		Gen_package(&info,M);
		send(socket,M,strlen(M),0);
	}
	else{
		INFO tmp;
		strcpy(tmp.Timestamp,info.Timestamp);
		tmp.Timestamp[18] =tmp.Timestamp[18]+1;
		strcpy(tmp.type,"0008");
		
		char M[4096];
		Gen_package(&tmp,M);
		
		int length = 4016;//des encryption
		char* extendC =(char*)malloc(sizeof(char)*length);
		//char* extendC1 =(char*)malloc(sizeof(char)*length);
		char* extendM =(char*)malloc(sizeof(char)*length);
		//char* extendM1 =(char*)malloc(sizeof(char)*length);
		memcpy(extendM,M+80,length);
		//Log("DES encryption",strlen("DES encryption"),1);
		//Log(extendM,length,1);
		//log DES加密 明文：
		//printf("%s\n",tmp.Key_c_v);
		DES_encryption((unsigned char* )extendM,length,(unsigned char*)info.Key_c_v,(unsigned char*)extendC);
		//DES_decryption((unsigned char* )extendC,(length/8 +1)*8,key,(unsigned char*)extendM1)
		//log DES加密 密文
		//Log(extendC,length,0);
		memcpy(M+80,extendC,length);
		
		send(socket,M,4096,0);
		free(extendC);
		free(extendM);
	}
}

void Respond_10(char* data,int socket,char* IP){
	char log[256];
	sprintf(log,"%s Certificate exchange",IP);
	//Log(log,strlen(log),1);
	INFO info ={""};
	Analysis(data,strlen(data),&info);
	char clientPk[64];
	memset(clientPk,0,64);
	sprintf(clientPk,"%s.txt",IP);
	FILE* file =fopen(clientPk,"w");
	fprintf(file,"%s\n%s\n%s",info.ID_c,info.Publickey_n,info.Publickey_e);
    fclose(file);
	
	INFO tmp={""};
	file =fopen("certificate.txt","r");
	fscanf(file,"%s\n%s\n%s",tmp.ID_v,tmp.Publickey_n,tmp.Publickey_e);
	strcpy(tmp.type,"0011");
	char M[4096];
	Gen_package(&tmp,M);
	send(socket,M,4096,0);
}

void Respond_12(char* data,int socket,char* IP,unsigned char* key){//密钥交换
	char log[256];
	sprintf(log,"%s Sessionkey exchange",IP);
	//Log(log,strlen(log),1);
	
	
	INFO info ={""};
	Analysis(data,strlen(data),&info);
	printf("%s\n",info.Data);
	
	FILE* file =fopen("ticketTmp.txt","w");
	fwrite(info.Data,1,strlen(info.Data),file);
	//fprintf(file,"%s",info.Data);
	fclose(file);
	//Log("RSA decryption",strlen("RSA decryption"),1);
	//Log(info.Data,strlen(info.Data),1);
	RSA_decryption("ticketTmp.txt","Sk.txt","result.txt");
	
	file =fopen("result.txt","r");
	fscanf(file,"%s",key);
	printf("%s",key);
	//Log((char*)key,strlen((char*)key),1);
	
	/*char cmd[256];
	sprintf(cmd,"rm %s %s","ticketTmp.txt","result.txt");
	file =popen(cmd,"r");
	pclose(file);*/
}

void Respond_13(char* data,int socket,char* IP){
	char log[256];
	sprintf(log,"%s Request all data",IP);
	//Log(log,strlen(log),1);
	char CMD1[] ={"select * from Info"};
	char filename[32];
	sprintf(filename,"%sInfo.txt",IP);
	findDB("WS",CMD1,filename);
	Concealment(filename);
	FILE* file =fopen(filename,"r");
	fseek(file,0,SEEK_END);
	int size =ftell(file);
	rewind(file);
	/*char* info =(char*)malloc(sizeof(char)*size);
	fread(info,1,size,file);
	int i =0;*/
	while(size >0){
		int count =size<1024?size:1024;
		INFO tmp ={""};
		strcpy(tmp.type,"0013");
		fread(tmp.Data,1,count,file);
		char M[4096];
		Gen_package(&tmp,M);
		//printf("%s\n",M);
		send(socket,M,4096,0);
		size -=1024;
	}
	fclose(file);
}

void Respond_14(char* data,int socket,char* IP,unsigned char* key){//特定数据获取
	char log[256];
	sprintf(log,"%s Request data",IP);
	//Log(log,strlen(log),1);
	
    INFO info={""};
	Analysis(data,strlen(data),&info);
	char keyfilepath[32];
	memset(keyfilepath,0,32);
	sprintf(keyfilepath,"%s.txt",IP);
	if (RAS_authentic(info.Data,info.Signature,keyfilepath) ==0){//Signature：Data的MD5结果RSA加密
		INFO tmp={""};
		strcpy(tmp.type,"0017");
		char M[4096];
		Gen_package(&tmp,M);
		send(socket,M,4096,0);
	}
	else{
		
		char CMD1[256];
		sprintf(CMD1,"select PhoneNum from Info where ID ='%s'",info.Data);
		char filename[32];
		sprintf(filename,"%sPhoneNum.txt",IP);
		if(findDB("WS",CMD1,filename) != -1){
			INFO tmp={""};
			strcpy(tmp.type,"0016");
			FILE* file =fopen(filename,"r");
			fscanf(file,"%s",tmp.Data);
			fclose(file);//gen data
			
			
			unsigned char result[16];
			MD5IN((unsigned char *)tmp.Data,result);
			file =fopen("sigTmp.txt","w");
			for(int i=0;i<16;i++){
				fprintf(file,"%02x",result[i]);
			}
			fclose(file);
			RSA_encryption("sigTmp.txt","Sk.txt","result.txt");
			file =fopen("result.txt","r");
			fscanf(file,"%s",tmp.Signature);
			//Log(info->Ticket,strlen(info->Ticket),1);
			fclose(file);//gen Signature
			
			char M[4096];
			Gen_package(&tmp,M);//gen package
			
			int length = 4016;//des encryption
			char* extendC =(char*)malloc(sizeof(char)*length);
			//char* extendC1 =(char*)malloc(sizeof(char)*length);
			char* extendM =(char*)malloc(sizeof(char)*length);
			//char* extendM1 =(char*)malloc(sizeof(char)*length);
			memcpy(extendM,M+80,length);
			//Log("DES encryption",strlen("DES encryption"),1);
			//Log(extendM,length,1);
			//log DES加密 明文：
			printf("%s\n",key);
			DES_encryption((unsigned char* )extendM,length,key,(unsigned char*)extendC);
			//DES_decryption((unsigned char* )extendC,(length/8 +1)*8,key,(unsigned char*)extendM1)
			//log DES加密 密文
			Log(extendC,length,0);
			memcpy(M+80,extendC,length);
			send(socket,M,4096,0);
			free(extendC);
			free(extendM);
		}
		
	}
}

void Respond_17(char* data,int socket,char* IP,unsigned char* key){//RSA出错反馈
	char log[256];
	sprintf(log,"%s RSA ERROR",IP);
	//Log(log,strlen(log),1);
	Respond_14(data,socket,IP,key);
}

void Respond_V(char* data,int socket,char* IP,unsigned char* sessionKey){
	char log[1024];
	sprintf(log,"%s Authentication Request",IP);
	//Log(log,strlen(log),1);
	
	char type[4];
	memcpy(type,data,4);//获取包类型
	if(strcmp(type,"0007") ==0){
		Respond_7(data,socket,IP);
	}
	else if(strcmp(type,"0010") ==0){
		Respond_10(data,socket,IP);
	}
	else if(strcmp(type,"0012") ==0){
		Respond_12(data,socket,IP,sessionKey);
	}
	else if(strcmp(type,"0013") ==0){
		Respond_13(data,socket,IP);
	}
	else if(strcmp(type,"0014") ==0){
		Respond_14(data,socket,IP,sessionKey);
	}
	else if(strcmp(type,"0017") ==0){
		Respond_17(data,socket,IP,sessionKey);
	}
	else{
		//Log("Unknow package type",strlen("Unknow package type"),1);
	}
	/*INFO tmp ={""};
	Analysis(data,strlen(data),&tmp);
	char CMD1[256],CMD2[256];
	sprintf(CMD1,"select Password_Hash from User where ID_c ='%s'",tmp.ID_c);
	sprintf(CMD2,"select * from TGS where ID_tgs ='%s'",tmp.ID_tgs);
	if((findDB("WS",CMD1,"User.txt") == -1) || (findDB("WS",CMD2,"TGS.txt") ==-1)){
		char M[4096];
		strcpy(tmp.type,"0003");
		Gen_package(&tmp,M);
		send(socket,M,strlen(M),0);
	}
	else{
		unsigned char key[8]={"1111111"};
		//md5 to 56
		sprintf(tmp.Key_c_tgs,"%d",rand()%9000000+1000000);
		strcpy(tmp.AD_c,IP);
		strcpy(tmp.type,"0002");
		gen_ticket(&tmp,"TGS.txt");
		gen_TS(tmp.Timestamp);
		strcpy(tmp.Lifetime,"0300");//gen info
		
		
		
		char M[4096];
		Gen_package(&tmp,M);//gen package
		
		int length = 4016;//des encryption
		char* extendC =(char*)malloc(sizeof(char)*length);
		//char* extendC1 =(char*)malloc(sizeof(char)*length);
		char* extendM =(char*)malloc(sizeof(char)*length);
		//char* extendM1 =(char*)malloc(sizeof(char)*length);
		memcpy(extendM,M+80,length);
		Log("DES encryption",strlen("DES encryption"),1);
		Log(extendM,length,1);
		//log DES加密 明文：
		DES_encryption((unsigned char* )extendM,length,key,(unsigned char*)extendC);
		//DES_decryption((unsigned char* )extendC,(length/8 +1)*8,key,(unsigned char*)extendM1)
		//log DES加密 密文
		Log(extendC,length,0);
		memcpy(M+80,extendC,length);
		//strncpy(M+80,extendC,(length/8 +1)*8);
		//memcpy(extendC1,M+80,length);
		//DES_decryption((unsigned char* )extendC1,(length/8 +1)*8,key,(unsigned char*)extendM1);
		send(socket,M,4096,0);
		free(extendC);
		free(extendM);
		//free(extendC1);
		//free(extendM1);
	}
	
	char cmd[256];
	sprintf(cmd,"rm %s %s","TGS.txt","User.txt");
	FILE* file =popen(cmd,"r");
	pclose(file);*/
}



