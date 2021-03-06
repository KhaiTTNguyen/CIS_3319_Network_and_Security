// Khai Nguyen
// Filename: header.h
// Usage to build class and declare functions

#ifndef HEADER_H
#define HEADER_H

// Include libraries
#include <iostream>
#include <fstream> // file opss
#include <set> // for set operations 
#include <vector>
#include <string>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h> // for size_t
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>
#include <unordered_set>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <cmath>
#include <fstream>
#include <bitset>
#include <sstream>
#include <time.h>

using namespace std;

#define MAX_BUFFER_LENGTH 8192
#define ITERATION 16
#define ID_c "CIS3319USERID"
#define ID_v "CIS3319SERVERID"
#define ID_tgs "CIS3319TGSID"
#define LIFE_TIME_2 60 
#define LIFE_TIME_4 86400

void generate_keys(string key, string round_keys[]);
string convertDecimalToBinary(int decimal);
int convertBinaryToDecimal(string binary);
string shift_left_once(string key_chunk);
string shift_left_twice(string key_chunk);
string Xor_32(string a, string b);
string Xor_48(string a, string b);
string DES_encryption(string plain_text, string round_keys[]);
string TextToBinaryString(string words);
string BinaryStringToText(string binaryString);
string generateCipher(string binary_text, string encryption_round_keys[]);
string generatePlain (string cipher_text, string decryption_round_keys[]);

#endif

/*
printf("%s\n", ID_tgs);
    printf("%s\n", ID_C);
    string s = string(ID_C) + string(ID_tgs);
    cout << s << endl;
    cout << s.substr(strlen(ID_C), strlen(ID_tgs));
*/