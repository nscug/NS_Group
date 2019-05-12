# -*- coding: utf-8 -*-
import time
import sys


def exp_mode(base, exponent, n):
    bin_array = bin(exponent)[2:][::-1]
    length = len(bin_array)
    base_array = [base]
    for _ in range(length - 1):
        base_array.append(base_array[-1] ** 2 % n)
    answer = 1
    for index in range(length):
        answer = answer * base_array[index] * int(bin_array[index]) if int(bin_array[index]) else answer
        answer %= n
    return answer % n


def _modulo(base, exponent, mod):
    x, y = 1, base
    while exponent > 0:
        if exponent % 2 == 1:
            x = (x * y) % mod
        y = (y * y) % mod
        exponent //= 2
    return x % mod


def toNum(string):
    Num =""
    for char in string:
        value =ord(char)
        Num =Num +str(value) if value >=100 else Num+"0"+str(value)
    return int(Num)

def toStr(num):
    nums = []
    while num > 0:
        nums.append(num % 1000)
        num = (num - nums[-1]) //1000
    nums.reverse()
    string = ''
    for i in nums:
        string += chr(i)
    return string

def encryption(info):
    infos =info.split(";")
    _encryption(infos[0],infos[1],infos[2])

def _encryption(sourceFilePath, keyFilePath, resultFilePath):
    with open(sourceFilePath, 'r') as file:
        M = file.read()
    length =len(M)

    with open(keyFilePath, 'r') as file:
        key = file.readlines()
    key_n, key_e = int(key[1]), int(key[2])

    with open(resultFilePath, 'w') as file:
        while length > 0:
            string, M = M[:100], M[100:]
            length -= 100
            m = toNum(string)
            print(m)
            c = _modulo(m, key_e, key_n)
            print(c)
            file.write(str(c) + "\n")



def decryption(info):
    infos =info.split(";")
    _decryption(infos[0],infos[1],infos[2])

def _decryption(sourceFilePath, keyFilePath, resultFilePath):
    with open(sourceFilePath, 'r') as file:
        C = file.readlines()

    with open(keyFilePath, 'r') as file:
        key = file.readlines()
    key_n, key_d = int(key[1]), int(key[2])

    with open(resultFilePath, 'w') as file:
        M = ""
        for c in C:
            tmp =int(c)
            data = _modulo(tmp, key_d, key_n)
            m = toStr(data)
            M = M + m
        file.write(M)

def main(argv):
	_decryption(argv[1],argv[2],argv[3])
	
if __name__=="__main__":
	main(sys.argv)