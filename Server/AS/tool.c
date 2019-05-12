#include "tool.h"
#include "des.h"

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
		
		
		//Log((char*)extend_key,56,0);
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
		

        for(int i =0;i <64;i++){
            printf("%d",extend_key[i]);
        }
        printf("\n");

        myReduce8_1(extend_M,_M);
		

        memcpy(M+index,_M,8);
        index+=8;
        length-=8;
    }
}

void gen_ticket(INFO* info,char* keyFilePath){
	char key_c_tgs[10],ID_c[20],AD_c[20],ID_tgs[20],TS[20],lifeTime[5];
	memset(key_c_tgs,0,10);memset(ID_c,0,20);memset(AD_c,0,20);memset(ID_tgs,0,20);memset(TS,0,20);memset(lifeTime,0,5);
	strcpy(key_c_tgs,info->Key_c_tgs);strcpy(ID_c,info->ID_c);strcpy(AD_c,info->AD_c);strcpy(ID_tgs,info->ID_tgs);strcpy(lifeTime,"0300");
	gen_TS(TS);
	char data[100];
	memset(data,0,100);
	strcat(data,key_c_tgs);strcat(data,";");
	strcat(data,ID_c);strcat(data,";");
	strcat(data,AD_c);strcat(data,";");
	strcat(data,ID_tgs);strcat(data,";");
	strcat(data,TS);strcat(data,";");
	strcat(data,lifeTime);
	FILE* file =fopen("ticketTmp.txt","w"); 
	fwrite(data,1,strlen(data),file);
	fclose(file);
	//Log("RSA Encryption",strlen("RSA Encryption"),1);
	//Log(data,strlen(data),1);
	RSA_encryption("ticketTmp.txt",keyFilePath,"result.txt");
	file =fopen("result.txt","r");
	fscanf(file,"%s",info->Ticket);
	//Log(info->Ticket,strlen(info->Ticket),1);
	fclose(file);
	
	char cmd[256];
	sprintf(cmd,"rm %s %s","ticketTmp.txt","result.txt");
	file =popen(cmd,"r");
	pclose(file);
}

int findDB(char* DBName,char* CMD,char* rFilePath){
	MYSQL mysql;
	MYSQL_RES *res;
	MYSQL_ROW row;
	int t,flag;
	mysql_init(&mysql);
	if(!mysql_real_connect(&mysql,"localhost","root","root",DBName,0,NULL,0)){
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

void Respond_As(char* data,int socket,char* IP){
	INFO tmp ={""};
	printf("%s\n",data+80);
	Analysis(data,strlen(data),&tmp);
	printf("%s\n",tmp.ID_c);
	char log[1024];
	sprintf(log,"%s Authentication Request",IP);
	//Log(log,strlen(log),1);
	char CMD1[256],CMD2[256];
	sprintf(CMD1,"select Password_Hash from User where ID_c ='%s'",tmp.ID_c);
	sprintf(CMD2,"select * from TGS where ID_tgs ='%s'",tmp.ID_tgs);
	
	char filename1[32],filename2[32];
	sprintf(filename1,"%sUser.txt",IP);
	sprintf(filename2,"%sTGS.txt",IP);
	if((findDB("WS",CMD1,filename1) == -1) || (findDB("WS",CMD2,filename2) ==-1)){
		char M[4096];
		strcpy(tmp.type,"0003");
		Gen_package(&tmp,M);
		send(socket,M,strlen(M),0);
	}
	else{
		
		unsigned char md5[32],key[7];
		FILE* file =fopen(filename1,"r");
		fscanf(file,"%s",md5);
		//printf("%s",md5);
		MD5to56(md5,key);
		//printf("%s",key);
		
		//md5 to 56
		sprintf(tmp.Key_c_tgs,"%d",rand()%9000000+1000000);
		strcpy(tmp.AD_c,IP);
		strcpy(tmp.type,"0002");
		gen_ticket(&tmp,filename2);
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
		//Log("DES encryption",strlen("DES encryption"),1);
		//Log(extendM,length,1);
		//log DES加密 明文：
		DES_encryption((unsigned char* )extendM,length,key,(unsigned char*)extendC);
		//DES_decryption((unsigned char* )extendC,(length/8 +1)*8,key,(unsigned char*)extendM1)
		//log DES加密 密文
		//Log(extendC,length,0);
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
	/*char cmd[256];
	sprintf(cmd,"rm %s %s","TGS.txt","User.txt");
	FILE* file =popen(cmd,"r");
	pclose(file);*/
}



