#ifndef Alice_h
#define Alice_h
#include <iostream>
#include <string>
#include <vector>
#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include <stdlib.h>
#include <sstream>
#include "../CommLib/NetComm/include/EtherReceiver.hpp"
#include "../CommLib/NetComm/include/EtherSender.hpp"
#include "../CommLib/NetComm/include/UDPSender.hpp"
#include "../CommLib/NetComm/include/UDPReceiver.hpp"
#include "../CryptoLib/include/Cryptor.hpp"
#include "../UserType.hpp"
#define STATE___init 0
#define STATE___final 1
#define STATE__Alice_State_1 2
#define STATE__Alice_State_2 3
#define STATE__Verify_State 4
#define STATE__Alice_State_3 5
static char* alice_swap;
static pcap_t* devAlice;
static char* aliceTempData;
class Alice {
	public: 
		int nonce;
		int alice;
		ByteVec pka;
		ByteVec pkb;
		ByteVec ska;
		ByteVec msgAlice1;
		ByteVec msgBob1;
		ByteVec msgAlice2;
		ByteVec SymEnc(Cryptor cryptor, ByteVec msg, char* key);
		ByteVec SymDec(Cryptor cryptor, ByteVec msg, char* key);
		int receiveMsg(ByteVec& msg);
		int sendMsg(ByteVec msg);
		int sendPk(ByteVec msg);
};
static int __currentState = STATE___init;
int main(int argc, char** argv) {
	Alice a;
	a.nonce = 1234;
	a.alice = 0;
	a.pka.content = "aaaaaaaaaaaaaaaa";
	a.pkb.content = "bbbbbbbbbbbbbbbb";
	a.ska.content = "aaaaaaaaaaaaaaaa";

	std::cout << "1" << std::endl;
	while(__currentState != -100) {
		switch(__currentState){
			case STATE___init:{
				std::cout << "------------------STATE___init" << std::endl;
				__currentState = STATE__Alice_State_1;
				break;
			}
			case STATE___final:{
				std::cout << "------------------STATE___final" << std::endl;
				std::cout << "FINISHED!!!" << std::endl;
				__currentState = -100;
				break;
			}
			case STATE__Alice_State_1:{

					std::cout << "------------------STATE__Alice_State_1" << std::endl;
					ByteVec msgA1;
					msgA1.nonce = a.nonce;
					msgA1.id = a.alice;
					a.msgAlice1 = msgA1;
					//TODO: configure a.pkb
					ByteVec sendMsgA1 = a.SymEnc(ctor, msgA1, (char*)a.pkb.content.c_str());
					std::cout << "Alice Encryption End: " << sendMsgA1.content << std::endl;
					a.sendMsg(sendMsgA1);
					__currentState = STATE__Alice_State_2;
					break;
			}
			case STATE__Alice_State_2:{

					std::cout << "------------------STATE__Alice_State_2" << std::endl;
					ByteVec msgFromB1;
					std::cout << "Receive message" << std::endl;
					a.receiveMsg(msgFromB1);
					std::cout << "Receive message end" << std::endl;
					std::cout << "decryption: " << (char *)a.ska.content.c_str() << std::endl; 
					ByteVec msgB1 = a.SymDec(ctor, msgFromB1, (char *)a.ska.content.c_str());
					std::cout << "decryption end" << std::endl;
					a.msgBob1 = msgB1;
					__currentState = STATE__Verify_State;
					break;
			}
			case STATE__Verify_State:{
					std::cout << "------------------STATE__Verify_State" << std::endl;
					if(a.msgBob1.nonce1 == a.nonce){
						__currentState = STATE__Alice_State_3;
					} else {
						std::cout << "Verify failed" << std::endl;
					}
					break;

			}
			case STATE__Alice_State_3:{
					std::cout << "------------------STATE__Alice_State_3" << std::endl;
					ByteVec msgA2;
					msgA2.id = a.alice;
					msgA2.nonce = a.msgBob1.nonce2;
					a.msgAlice2 = msgA2;
					ByteVec sendMsgA2 = a.SymEnc(ctor, msgA2, (char*)a.pkb.content.c_str());
					a.sendMsg(sendMsgA2);
					__currentState = STATE___final;
					break;
			}
			default: break;
		}
	}
}
#endif

