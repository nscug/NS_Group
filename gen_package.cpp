#include "Gen_package.h"

//INFO info = { "1","c111","","tgs111","","","","","2019.04.27.19:47:02","","","","","" };

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

void Gen_package(INFO info, char* package) {
	int i = 0;
	char* p = NULL;
	p = (char *)malloc(200*sizeof(char));
	char *pp = NULL;
	pp = (char *)malloc(4*sizeof(char));
	if (strcmp(info.type, "") == 0) {
		strcpy(package, "00-1");
	}
	else {
		strcpy(package, "0001");
		strcpy(p, info.type);
	}
	if (strcmp(info.ID_c, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p) + 1;
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info.ID_c);
	}
	if (strcmp(info.ID_v, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p) + 1;
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info.ID_v);
	}

	if (strcmp(info.ID_tgs, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p) + 1;
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info.ID_tgs);
	}
	if (strcmp(info.Key_c_tgs, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p) + 1;
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info.Key_c_tgs);
	}
	if (strcmp(info.Key_c_v, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p) + 1;
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info.Key_c_v);
	}
	if (strcmp(info.Publickey_v_n, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p) + 1;
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info.Publickey_v_n);
	}
	if (strcmp(info.Puclickey_v_e, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p) + 1;
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info.Puclickey_v_e);
	}
	if (strcmp(info.Timestamp, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p) + 1;
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info.Timestamp);
	}
	if (strcmp(info.Signature, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p) + 1;
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info.Signature);
	}
	if (strcmp(info.Lifetime, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p) + 1;
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info.Lifetime);
	}
	if (strcmp(info.Ticket, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p) + 1;
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info.Ticket);
	}
	if (strcmp(info.Sessionkey, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p) + 1;
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info.Sessionkey);
	}
	if (strcmp(info.Data, "") == 0) {
		strcat(package, "00-1");
	}
	else {
		i = strlen(p) + 1;
		i_c4(i, pp);
		strcat(package, pp);
		strcat(p, info.Data);
	}
	strcat(package, p);
	/*printf("%s\n", package);
	free(p);
	p = NULL;
	free(pp);
	pp = NULL;*/
}

/*
调用说明：
	char* package = NULL;
	package = (char *)malloc(200 * sizeof(char));
	Gen_package(info, package);
	……
	free(package);
	package = NULL;
*/

