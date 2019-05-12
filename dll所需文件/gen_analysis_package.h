#ifndef GEN_ANALYSIS_PACKAGE_H_INCLUDED
#define GEN_ANALYSIS_PACKAGE_H_INCLUDED

typedef struct
{
	char type[5];
	char ID_c[20];
	char ID_v[20];
	char ID_tgs[20];
	char AD_c[16];
	char Key_c_tgs[7];
	char Key_c_v[7];
	char Publickey_n[1024];
	char Publickey_e[8];
	char Timestamp[64];
	char Signature[1024];
	char Lifetime[8];
	char Ticket[1024];
	char Sessionkey[7];
	char Data[1024];
}INFO;

void Gen_package(INFO* info, char* package);

void Analysis(char* data, long long length, INFO* info);


#endif // GEN_ANALYSIS_PACKAGE_H_INCLUDED
