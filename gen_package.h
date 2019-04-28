#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <iostream>
#pragma warning(disable:4996)
typedef struct
{
	char type[4];
	char ID_c[20];
	char ID_v[20];
	char ID_tgs[20];
	char Key_c_tgs[7];
	char Key_c_v[7];
	char Publickey_v_n[1024];
	char Puclickey_v_e[8];
	char Timestamp[20];
	char Signature[16];
	char Lifetime[8];
	char Ticket[1024];
	char Sessionkey[7];
	char Data[1024];
}INFO;
