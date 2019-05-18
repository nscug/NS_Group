#include <stdio.h>
#include <stdlib.h>
#include "lib.h"
#include "tool.h"
#include "gen_analysis_package.h"
#pragma comment(lib,"ws2_32.lib")
//#include "C_respond.h"
#include "MD5.h"

int Authentication(char* ID, char* password){

    unsigned char key[7],key_c_tgs[]="0000000",key_c_v[]="0000000";
    char* package =(char*)malloc(sizeof(char)*4096);
    int length;
    char* extendM,*extendC;
    INFO tmp;
    char Pk_n_v[1024],Pk_n_e[64];
    FILE* file=NULL;

    struct IP_PORT_ID ip_port_id ={""};
    load_info(&ip_port_id);//获取AS,TGS,V的IP和PORT以及ID_tgs,ID_v

    int AS_socket=-1,TGS_socket=-1,V_socket=-1;
    Log("connect AS",strlen("connect AS"),1);
    AS_socket =connect_server(ip_port_id.AS_IP,ip_port_id.AS_PORT);//连接AS,TGS,V
    TGS_socket = connect_server(ip_port_id.TGS_IP,ip_port_id.TGS_PORT);
    V_socket =connect_server(ip_port_id.V_IP,ip_port_id.V_PORT);
    if(AS_socket ==-13 || TGS_socket == -13 || V_socket ==-13){
        //Log 记录连接
        closesocket(AS_socket);
        closesocket(TGS_socket);
        closesocket(V_socket);
        return -1;
    }


    //*****************************************AS 认证开始***************//
    INFO info={""};//生成一号报文所需信息
    strcpy(info.type,"0001");
    strcpy(info.ID_c,ID);
    strcpy(info.ID_tgs,ip_port_id.TGS_ID);
    gen_TS(&info.Timestamp);//信息生成完成
    Gen_package(&info,package);//打包
    if(send(AS_socket,package,strlen(package)+1,0) ==-1){//发送
        closesocket(AS_socket);
        closesocket(TGS_socket);
        closesocket(V_socket);
        Log("ERROR send to AS",strlen("ERROR send to AS"),1);
        return 0;
    }
    memset(package,0,4096);

    if(recv(AS_socket,package,4096,0) <1){//接收反馈
        closesocket(AS_socket);
        closesocket(TGS_socket);
        closesocket(V_socket);
        Log("ERROR recv from AS",strlen("ERROR recv from AS"),1);
        return 0;
    }

    memset(&tmp,0,sizeof(tmp));
    //Analysis(package,strlen(package),&tmp);


    char type[]="0000";//处理报文
    strncpy(type,package,4);
    //type[5] ='\0';
    //int packageType;
    //sscanf(type,"%d",packageType);
    if(strcmp(type,"0002") == 0){
		unsigned char result[16], md5[] = "00000000000000000000000000000000";
        MD5IN((unsigned char *)password,result);
        for(int i=0;i<16;i++){
            sprintf(md5+i*2,"%02x",result[i]);
        }
        MD5to56(md5,key);
        //md5 + md5to56*******************************************
        length =4016;
        extendC =(char*)malloc(sizeof(char)*4016);
        extendM =(char*)malloc(sizeof(char)*4016);
        memcpy(extendC,package+80,length);

        Log("DES decryption",strlen("DES decryption"),1);
		file =fopen("AS_decryption.txt","w");
		fwrite(extendC,1,length,file);
        Log(extendC,length,0);
        DES_decryption(extendC,length,key,extendM);
        Log(extendM,length,1);
		fwrite(extendM,1,length,file);
		fclose(file);
        memcpy(package+80,extendM,length);
        memset(&tmp,0,sizeof(tmp));
        Analysis(package,strlen(package),&tmp);
        if(strcmp(type,tmp.type) != 0){
            closesocket(AS_socket);
            closesocket(TGS_socket);
            closesocket(V_socket);
            Log("Authentic filed",strlen("Authentic filed"),1);
            return 0;
        }
        strcpy(key_c_tgs,tmp.Key_c_tgs);
        free(extendC);
        free(extendM);
        //printf("%s\n",tmp.Ticket);
        //**********************************AS 认证完成****************//

        //******************************TGS 票据请求开始*****************//
        Log("Connect TGS",strlen("Connect TGS"),1);
        memset(package,0,4096);
        memset(&info,0,sizeof(info));
        strcpy(info.type,"0004");//生成4号报文信息
        strcpy(info.ID_v,ip_port_id.V_ID);
        memcpy(info.Ticket,tmp.Ticket,1024);
        strcpy(info.ID_c,ID);
        get_local_ip(info.AD_c);
        gen_TS(info.Timestamp);//报文信息生成完成
        Gen_package(&info,package);//打包
        if(send(TGS_socket,package,strlen(package)+1,0) ==-1){//发送
            closesocket(AS_socket);
            closesocket(TGS_socket);
            closesocket(V_socket);
            Log("ERROR send to TGS",strlen("ERROR send to TGS"),1);
            return 0;
        }

        memset(package,0,4096);

        if(recv(TGS_socket,package,4096,0) <1){//接收反馈
            closesocket(AS_socket);
            closesocket(TGS_socket);
            closesocket(V_socket);
            Log("ERROR recv from TGS",strlen("ERROR recv from TGS"),1);
            return 0;
        }
        strncpy(type,package,4);//处理报文
        //type[5] ='\0';
        //packageType =atoi(type);
        if(strcmp(type,"0005") ==0){
            length =4016;
            extendC =(char*)malloc(sizeof(char)*4016);
            extendM =(char*)malloc(sizeof(char)*4016);
            memcpy(extendC,package+80,length);

            Log("DES decryption",strlen("DES decryption"),1);
            Log(extendC,length,0);
            DES_decryption(extendC,length,key_c_tgs,extendM);
            Log(extendM,length,1);
            memcpy(package+80,extendM,length);


        file =fopen("TGS_decryption.txt","w");
		fwrite(extendC,1,length,file);
        //Log(extendC,length,0);
        //DES_decryption(extendC,length,key,extendM);
        //Log(extendM,length,1);
		fwrite(extendM,1,length,file);
		fclose(file);
            memset(&tmp,0,sizeof(tmp));
            Analysis(package,strlen(package),&tmp);
            if(strcmp(tmp.type,type) != 0){
                closesocket(AS_socket);
                closesocket(TGS_socket);
                closesocket(V_socket);
                Log("ticket request filed",strlen("ticket request filed"),1);
                return 0;
            }
            strcpy(key_c_v,tmp.Key_c_v);
            free(extendC);
            free(extendM);
            //////****************************TGS 票据请求完成*******************///

            /////***********************V 服务请求****************************///
            memset(package,0,4096);
            memset(&info,0,sizeof(info));
            strcpy(info.type,"0007");//生成7号报文所需信息
            strcpy(info.Ticket,tmp.Ticket);
            strcpy(info.ID_c,ID);
            get_local_ip(info.AD_c);
            gen_TS(info.Timestamp);//报文信息生成完成

            Gen_package(&info,package);//打包
            if(send(V_socket,package,strlen(package)+1,0) ==-1){//发送
                closesocket(AS_socket);
                closesocket(TGS_socket);
                closesocket(V_socket);
                 Log("ERROR send to V",strlen("ERROR send to V"),1);
                return 0;
            }

            memset(package,0,4096);

            if(recv(V_socket,package,4096,0) <1){//接收反馈
                closesocket(AS_socket);
                closesocket(TGS_socket);
                closesocket(V_socket);
                 Log("ERROR recv from V",strlen("ERROR recv from V"),1);
                return 0;
            }
            strncpy(type,package,4);//处理报文
            //type[5] ='\0';
            //packageType =atoi(type);
            if( strcmp(type,"0008") ==0){
                length =4016;
                extendC =(char*)malloc(sizeof(char)*4016);
                extendM =(char*)malloc(sizeof(char)*4016);
                memcpy(extendC,package+80,length);

                Log("DES decryption",strlen("DES decryption"),1);
                Log(extendC,length,0);
                DES_decryption(extendC,length,key_c_v,extendM);
                Log(extendM,length,1);
                memcpy(package+80,extendM,length);

				file =fopen("V_decryption.txt","w");
				fwrite(extendC,1,length,file);
				//Log(extendC,length,0);
				//DES_decryption(extendC,length,key,extendM);
				//Log(extendM,length,1);
				fwrite(extendM,1,length,file);
				fclose(file);
                memset(&tmp,0,sizeof(tmp));
                Analysis(package,strlen(package),&tmp);
                if(strcmp(type,tmp.type) != 0){
                    closesocket(AS_socket);
                    closesocket(TGS_socket);
                    closesocket(V_socket);
                    Log("Service request filed",strlen("Service request filed"),1);
                    return 0;
                }
                free(extendC);
                free(extendM);
               ///////////////****************** V 服务请求完成***************///

               //////////////////************** C   V 交换证书************////
               memset(package,0,4096);
               memset(&info,0,sizeof(info));
               strcpy(info.type,"0010");//生成10号报文信息
               struct Certificate c_c;
               load_certificate(&c_c);
               strcpy(info.ID_c,c_c.ID);
               strcpy(info.Publickey_n,c_c.Pk_n);
               strcpy(info.Publickey_e,c_c.Pk_e);
               strcpy(info.Signature,c_c.signature);

               Gen_package(&info,package);//打包
               if(send(V_socket,package,strlen(package)+1,0) ==-1){//发送
                    closesocket(AS_socket);
                    closesocket(TGS_socket);
                    closesocket(V_socket);
                    Log("Send to V filed",strlen("Send to V filed"),1);
                    return 0;
                }

                memset(package,0,4096);

                if(recv(V_socket,package,4096,0) <1){//接收反馈
                    closesocket(AS_socket);
                    closesocket(TGS_socket);
                    closesocket(V_socket);
                    Log("Recv from V filed",strlen("Recv from V filed"),1);
                    return 0;
                }

                memset(&info,0,sizeof(info));
                Analysis(package,strlen(package),&info);
                file =fopen("V_certificate.txt","w");
                fprintf(file,"%s\n%s\n%s",info.ID_v,info.Publickey_n,info.Publickey_e);
                fclose(file);
				Log("certificate exchange success", strlen("certificate exchange success"), 1);
                /////*********************C  V  证书交换完成*********************///

                ////************************** C V 首次数据交换 明文**********////

                memset(package,0,4096);
                memset(&info,0,sizeof(info));
                strcpy(info.type,"0013");
                Gen_package(&info,package);
                if(send(V_socket,package,strlen(package),0) ==-1){//发送
                    closesocket(AS_socket);
                    closesocket(TGS_socket);
                    closesocket(V_socket);
                    Log("Send to V filed",strlen("Send to V filed"),1);
                    return 0;
                }

                memset(package,0,4096);

                file =fopen("data.txt","w");
                while(recv(V_socket,package,4096,0)  >1){
                    //printf("%s\n",package);
                    memset(&info,0,sizeof(info));
                    Analysis(package,strlen(package),&info);
                    fwrite(info.Data,sizeof(info.Data),1,file);
                    memset(package,0,4096);
                }
                fclose(file);
				Log("success", strlen("success"), 1);
				closesocket(AS_socket);
				closesocket(TGS_socket);
				return V_socket;
                /////////////***************** 完成****************//////////////////

            }
            else{
                Log("Service Request filed",strlen("Service Request filed"),1);
                return 0;
            }
        }
        else{
            Log("Ticket Request filed",strlen("Ticket Request filed"),1);
            return 0;
        }
    }
    else{
        Log("Authentic filed not find this ID",strlen("Authentic filed not find this ID"),1);
        return 0;
    }
}

int Search(char* ID,int Socket){
	char package[4096];
	unsigned char SessionKey[] = "0000000";
	INFO info = { "" };//生成12号报文所需信息
	strcpy(info.type, "0012");
	sprintf(info.Data, "%d", rand() % 9000000 + 1000000);
	for (int i = 0; i < 7; i++) {
		SessionKey[i] = info.Data[i];
	}
	//Log(info.Sessionkey,strlen(info.Sessionkey),1);
	FILE* file = fopen("SessionKeyTmp.txt", "w");
	fwrite(info.Data, 1, strlen(info.Data), file);
	fclose(file);
	Log("RSA Encryption", strlen("RSA Encryption"), 1);
	Log(info.Data, strlen(info.Data), 1);
	RSA_encryption("SessionKeyTmp.txt", "V_certificate.txt", "result.txt");
	file = fopen("result.txt", "r");
	fscanf(file, "%s", info.Data);
	Log(info.Data, strlen(info.Data), 1);
	fclose(file);

	memset(package, 0, 4096);
	Gen_package(&info, package);
	if (send(Socket, package, strlen(package) + 1, 0) == -1) {//发送
		closesocket(Socket);
		Log("Send to V filed", strlen("Send to V filed"), 1);
		return 0;
	}//交换会话密码


	memset(&info, 0, sizeof(info));
	strcpy(info.type, "0014");
	strcpy(info.Data, ID);

	unsigned char result[16] = "0000000000000000";
	MD5IN((unsigned char *)info.Data, result);
	file = fopen("sigTmp.txt", "w");
	for (int i = 0; i < 16; i++) {
		fprintf(file, "%02x", result[i]);
	}
	fclose(file);

	RSA_encryption("sigTmp.txt", "Sk.txt", "result.txt");
	file = fopen("result.txt", "r");
	fscanf(file, "%s", info.Signature);
	//Log(info->Ticket,strlen(info->Ticket),1);
	fclose(file);//gen Signature

	char M[4096];
	Gen_package(&info, M);
	send(Socket, M, 4096, 0);//发送请求

	memset(package, 0, 4096);//接收数据
	recv(Socket, package, 4096, 0);

	int length = 4016;
	char* extendC = (char*)malloc(sizeof(char) * 4016);
	char* extendM = (char*)malloc(sizeof(char) * 4016);
	memcpy(extendC, package + 80, length);

	Log("DES decryption", strlen("DES decryption"), 1);
	Log(extendC, length, 0);
	DES_decryption(extendC, length, SessionKey, extendM);
	Log(extendM, length, 1);
	memcpy(package + 80, extendM, length);

	memset(&info, 0, sizeof(info));
	Analysis(package, strlen(package), &info);


	Log("RSA signature authentic",strlen("RSA signature authentic"),1);
	int i = RSA_authentic(info.Data, info.Signature, "V_certificate.txt");//0 RSA签名认证成功
	if (i == 0) {
		file = fopen("phoneNum.txt", "w");
		fprintf(file, "%s", info.Data);
		fclose(file);
		return 1;
	}
	else {
		return 0;
	}

}
