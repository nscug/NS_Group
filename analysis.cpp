#include "gen_package.h"

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
		strcpy(info->Publickey_v_n, p);
	}
	else if (i == 32) {
		strcpy(info->Puclickey_v_e, p);
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

void Analysis(char* data, long long length, INFO* info) {
	char p[] = "0000";
	char q[] = "0000";
	int b1 = 0;
	int b2 = 0;
	int j = 0;
	for (int i = 0; i < 53; i = i + 4) {
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
			while (j < 56) {
				q[0] = data[j];
				q[1] = data[j + 1];
				q[2] = data[j + 2];
				q[3] = data[j + 3];
				if (strcmp(q, "00-1") == 0) {
					j = j + 4;
					continue;
				}
				else {
					b1 = c4_i(p);
					b2 = c4_i(q);
					char pp[1024] = { 0 };
					for (int m = b1; m < b2; m++) {
						pp[m - b1] = data[m+79];
					}
					cpy(info, i, pp);
					break;
				}
			}
			if (i == 52) {
				b1 = c4_i(p);
				char pp[1024] = { 0 };
				for (int m = b1; m <= length; m++) {
					pp[m - b1] = data[m+79];
				}
				cpy(info, i, pp);
			}
		}
	}
}

/*调用说明：
	INFO *info;
	INFO info1 = { "","","","","","","","","","","","","","","" };
	info = &info1;
	char package[] = "0001000200-1000600-100-100-100-100-1001200-100-100-100-100-1000000000000000000001c111tgs1112019.04.27.19:47:02";
	long long length = strlen(package);
	Analysis(package, length, info);
*/