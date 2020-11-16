#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include "../CommLib/NetComm/include/packet.hpp"
#include <unistd.h>
#include <memory.h>

typedef struct innerStruct {

    int i;
    int j;
} innerStruct;

typedef struct testStruct {
    innerStruct s;
    char k;
    char m[6];
} testStruct;


int main(){
testStruct* tempDataGateway;
GwAnce gwAnce;

gwAnce.auth_hdr.length = sizeof(GwAnce) - sizeof(auth_header);
std::cout << "gwAnce length: " << gwAnce.auth_hdr.length << std::endl;
gwAnce.auth_hdr.serial_num = 1;
gwAnce.auth_hdr.type = 0x01;
gwAnce.auth_hdr.version = 1;
//TODO: configure gateway ip and mac here
gwAnce.gateway_id.byte1 = 255;
gwAnce.gateway_id.byte2 = 255;
gwAnce.gateway_id.byte3 = 255;
gwAnce.gateway_id.byte4 = 255;
gwAnce.gateway_mac[0] = 0x11;
gwAnce.gateway_mac[1] = 0x11;
gwAnce.gateway_mac[2] = 0x11;
gwAnce.gateway_mac[3] = 0x11;
gwAnce.gateway_mac[4] = 0x11;
gwAnce.gateway_mac[5] = 0x12;
//TODO: configure random number here
gwAnce.gateway_random_number = 0;


std::cout << "gwAnce gateway_id byte1: " << gwAnce.gateway_id.byte1 << std::endl;
time_t t;
time(&t);
gwAnce.auth_hdr.timestamp = 0;
//TODO: add memcpy here
char* output = (char*)&gwAnce;
std::cout << sizeof(GwAnce) << std::endl;

tempDataGateway = (testStruct*)malloc(sizeof(GwAnce) * sizeof(char));
memcpy(tempDataGateway, &gwAnce, sizeof(GwAnce));
GwAnce *gwa = (GwAnce*)tempDataGateway;
std::cout << "TESTTEST: " << gwa->auth_hdr.version << std::endl;
std::cout << "tempDataGateway: " << tempDataGateway << std::endl;

free(tempDataGateway);
testStruct str;
str.s.i = 1;
str.s.j = 2;
str.k = 'a';

str.m[0] = 'b';
str.m[1] = 'a';
str.m[2] = 'b';

str.m[3] = 'b';
str.m[4] = 'b';
str.m[5] = 'b';
testStruct str2;
str2 = str;
tempDataGateway = (struct testStruct*)malloc(sizeof(testStruct));
memcpy(tempDataGateway, (char*)&str, sizeof(testStruct));
testStruct* ts = (testStruct*)tempDataGateway;
std::cout << tempDataGateway << std::endl;
std::cout << ts->s.i << std::endl;
std::cout << ts->s.j << std::endl;
std::cout << ts->k << std::endl;
std::cout << ts->m[4] <<std::endl;
std::cout << ts->m << std::endl;
}