#ifndef LIB_H_INCLUDED
#define LIB_H_INCLUDED

#ifdef __cplusplus
#define EXPORT extern "C" __declspec (dllexport)
#else
#define EXPORT __declspec (dllexport)
#endif // __cplusplus

#include <windows.h>

EXPORT  int Authentication(char* ID,char* password);
EXPORT  int Search(char *ID,int socket);


#endif // LIB_H_INCLUDED
