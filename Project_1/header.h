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


using namespace std;

#define MAX_BUFFER_LENGTH 1500
#define ITERATION 16


void generate_keys(string key, string round_keys[]);
string convertDecimalToBinary(int decimal);
int convertBinaryToDecimal(string binary);
string shift_left_once(string key_chunk);
string shift_left_twice(string key_chunk);
string Xor(string a, string b);

string DES_encryption(string plain_text, string round_keys[]);
#endif
