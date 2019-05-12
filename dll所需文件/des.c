#include "des.h"
#include <stdio.h>
#include <string.h>

void myExtend1_8(unsigned char* source, unsigned char* result){
    unsigned char tmp ='\0';
    for(int i =0;i <64;i++){
        tmp =source[i/8]<<(i%8);
        result[i] =tmp>>7;
    }
}

void extendKey(unsigned char* source, unsigned char* result) {
	unsigned char tmp = '\0';
	for (int i = 0; i < 56; i++) {
		tmp = source[i / 8] << (i % 8);
		result[i] = tmp >> 7;
	}
}

void myReduce8_1(unsigned char* source, unsigned char* result){
    unsigned char tmp ='\0';
    for(int i =0;i <64;i++){
        result[i/8] =result[i/8]<<1;
        tmp =source[i]<<7;
        //printf("%d ",tmp>>7);
        result[i/8] +=tmp>>7;
    }
}

void IP(unsigned char* data){
    unsigned char* tmp =(unsigned char*)malloc(sizeof(unsigned char)*64);
    for(int i =0; i<64;i++){
        tmp[i] =data[IPTable[i]-1];
    }
    for(int i =0;i <64;i++){
        data[i] =tmp[i];
    }
    free(tmp);
    /*unsigned char tmp ='\0';
    for(int i =0;i <64;i++){
        tmp =data[i];
        int index =IPTable[i];
        while(index <i){
            index =IPTable[index];
        }
        data[i] =data[index-1];
        data[index-1] =tmp;
    }*///test version
}

void end_IP(unsigned char* data){
    unsigned char* tmp =(unsigned char*)malloc(sizeof(unsigned char)*64);
    for(int i =0; i<64;i++){
        tmp[i] =data[endIP[i]-1];
    }
    for(int i =0;i <64;i++){
        data[i] =tmp[i];
    }
    free(tmp);
    /*unsigned char* tmp ='\0';
    for(int i =0;i <64;i++){
        tmp =data[i];
        int index =endIP[i];
        while(index <i){
            index =endIP[index];
        }
        data[i] =data[index-1];
        data[index-1] =tmp;
    }*/
}

void extend(unsigned char* source, unsigned char* result){
    for(int i =0; i <48;i++){
        result[i] =source[extendTable[i]-1];
    }
}

void Psubstitude(unsigned char* data){
    unsigned char* tmp =(unsigned char*)malloc(sizeof(unsigned char)*32);
    for(int i =0; i<32;i++){
        tmp[i] =data[substitudeTabel[i]-1];
    }
    for(int i =0;i <32;i++){
        data[i] =tmp[i];
    }
    free(tmp);
    /*unsigned char* tmp ='\0';
    for(int i =0;i <32;i++){
        tmp =data[i];
        int index =substitudeTabel[i];
        while(index <i){
            index =substitudeTabel[index];
        }
        data[i] =data[index-1];
        data[index-1] =tmp;
    }*/
}

void leftShift(unsigned char* data){
    unsigned char tmp;
    tmp =data[0];
    int i =0;
    for(;i <27;i++){
        data[i] =data[i+1];
    }
    data[i] =tmp;
}

void genSubkey(unsigned char* key){
    for(int i =0; i <16; i++){
        int offset =shift[i];
        for(int j =0;j <offset;j++){
            leftShift(key);
            leftShift(key+28);
        }
        for(int j =0; j<48;j++){
            subKeySet[i][j] =key[KeyReduce[j]];
        }
    }
}

unsigned char* getSubkey(int loop){
    return subKeySet[loop];
}

void Sbox(unsigned char* source, unsigned char* result){
    for(int i =0;i <8;i++){
        int row =(int)((source[i*6]<<1)+(source[i*6+5]));
        int col =(int)((source[i*6+1]<<3)+(source[i*6+2]<<2)+(source[i*6+3]<<1)+(source[i*6+4]));

        unsigned char value =Sboxes[i][row*16+col];
        for(int j =0;j <4;j++){
            unsigned char tmp =value <<(j+4);
            result[i*4+j] =tmp >>7;
        }
    }
}

void encryption(unsigned char* M,unsigned char* key,unsigned char* C){
    unsigned char L[32],R[32],tmpR[32];
    unsigned char* subKey;
    unsigned char extendR[48];

    genSubkey(key);
    IP(M);//step 1£ºIP ÖÃ»»
    memcpy(L,M,32);
    memcpy(R,M+32,32);

    for(int i =0; i <16; i++){
        memcpy(tmpR,R,32);
        subKey =getSubkey(i);
        extend(R,extendR);

        for(int j =0; j <48;j++){
            extendR[j] =extendR[j]^subKeySet[i][j];
        }
        Sbox(extendR,R);

        Psubstitude(R);

        for(int j =0;j <32;j++){
            R[j] =L[j]^R[j];
            L[j] =tmpR[j];
        }

    }

    for(int i =0;i <32;i++){
        C[i] =R[i];
        C[i+32] =L[i];
    }

    end_IP(C);
}

void decryption(unsigned char* C, unsigned char* key, unsigned char* M){
    unsigned char L[32],R[32],tmpR[32];
    //unsigned char* subKey;
    unsigned char extendR[48];

    genSubkey(key);
    IP(C);//step 1£ºIP ÖÃ»»
    memcpy(L,C,32);
    memcpy(R,C+32,32);

    for(int i =15; i >=0 ; i--){
        memcpy(tmpR,R,32);
        //subKey =getSubkey(i);
        extend(R,extendR);
        for(int j =0; j <48;j++){
            extendR[j] =extendR[j]^subKeySet[i][j];
        }
        Sbox(extendR,R);
        Psubstitude(R);
        for(int j =0;j <32;j++){
            R[j] =L[j]^R[j];
            L[j] =tmpR[j];
        }
    }

    for(int i =0;i <32;i++){
        M[i] =R[i];
        M[i+32] =L[i];
    }
    end_IP(M);
}
