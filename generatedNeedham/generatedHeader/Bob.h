#ifndef Bob_h
#define Bob_h
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
#define STATE__Bob_State_1 2
#define STATE__Bob_State_2 3
#define STATE__Bob_State_3 4
#define STATE__Verify_State2 5
static char* bob_swap;
static pcap_t* devBob;
static char* bobTempData;
class Bob {
	public:  
		int nonce;
		int bob;
		ByteVec pka;
		ByteVec pkb;
		ByteVec skb;
		ByteVec ma1;
		ByteVec msgAlice1;
		ByteVec msgBob1;
		ByteVec mb1;
		ByteVec ma2;
		ByteVec msgAlice2;
	
		ByteVec SymEnc(Cryptor cryptor, ByteVec msg, char* key);
		ByteVec SymDec(Cryptor cryptor, ByteVec msg, char* key);
		int receiveMsg(ByteVec& msg);
		int sendMsg(ByteVec msg);
		int recvPk(ByteVec& msg);

};

static int __currentState = STATE___init;
int main(int argc, char** argv) {
	Bob b;
	b.pka.content = "aaaaaaaaaaaaaaaa";
	b.pkb.content = "bbbbbbbbbbbbbbbb";
	b.skb.content = "bbbbbbbbbbbbbbbb";
	b.nonce = 4321;
	b.bob = 1;
	while(__currentState != -100) {
		switch(__currentState){
			case STATE___init:
			{
					std::cout << "------------------STATE___init" << std::endl;
					__currentState = STATE__Bob_State_1;
					break;
			}
			case STATE___final:{
					std::cout << "------------------STATE___final" << std::endl;
					std::cout << "FINISHED!!!" << std::endl;
					__currentState = -100;
					break;
			}

			case STATE__Bob_State_1:{
					std::cout << "------------------STATE__Bob_State_1" << std::endl;
					ByteVec msgFromA1;
					std::cout << "Receive message" << std::endl;
					b.receiveMsg(msgFromA1);
					std::cout << "Receive message end" << std::endl;
					ByteVec msgA1;
					std::cout << "decryption: " << (char *)b.skb.content.c_str() << std::endl; 
					msgA1 = b.SymDec(ctor, msgFromA1,(char *)b.skb.content.c_str());
					std::cout << "decryption end" << std::endl;
					b.msgAlice1 = msgA1;
					__currentState = STATE__Bob_State_2;
					break;
			}
			case STATE__Bob_State_2:{
					std::cout << "------------------STATE__Bob_State_2" << std::endl;
					ByteVec msgB1;
					msgB1.id = b.bob;
					msgB1.nonce1 = b.msgAlice1.nonce;
					msgB1.nonce2 = b.nonce;
					ByteVec sendMsgB1 = b.SymEnc(ctor, msgB1, (char*)b.pka.content.c_str());
					std::cout << "Bob Encryption End: " << sendMsgB1.content << std::endl;
					b.sendMsg(sendMsgB1);
					__currentState = STATE__Bob_State_3;
					break;
			}
					
			case STATE__Bob_State_3:{
					std::cout << "------------------STATE__Bob_State_3" << std::endl;
					ByteVec msgFromA2;
					b.receiveMsg(msgFromA2);
					ByteVec msgA2 = b.SymDec(ctor, msgFromA2,(char*)b.skb.content.c_str());
					b.msgAlice2 = msgA2;
					__currentState = STATE__Verify_State2;
					break;
			}
					
			case STATE__Verify_State2:{
					std::cout << "------------------STATE__Verify_State2" << std::endl;
					if(b.msgAlice2.nonce == b.nonce){
						__currentState = STATE___final;
					} else {
						std::cout << "Verify failed" << std::endl;
					}
					break;
			}
			default: break;
		}
	}
}
#endif

