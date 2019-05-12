#include "gen_analysis_package.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
	//free(p);
	////p = NULL;
	//free(pp);
	//pp = NULL;
}
