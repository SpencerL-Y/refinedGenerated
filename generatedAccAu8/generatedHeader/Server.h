#ifndef Server_h
#define Server_h
#include <iostream>
#include <string>
#include <vector>
#include <stdlib.h>
#include <thread>
#include <stdlib.h>
#include <sstream>
#include <stdio.h>
#include <thread>
#include <stdlib.h>
#include <typeinfo>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>
#include "../CommLib/NetComm/include/EtherReceiver.hpp"
#include "../CommLib/NetComm/include/EtherSender.hpp"
#include "../CommLib/NetComm/include/UDPSender.hpp"
#include "../CommLib/NetComm/include/UDPReceiver.hpp"
#include "../CryptoLib/include/Cryptor.hpp"
#include "../UserType.hpp" 
#define STATE___init 0
#define STATE___final 1
#define STATE__reqRecved 2
#define STATE__queCreated 3
#define STATE__verifyReqFailed 4
#define STATE__queSent 5
#define STATE__queRespRecved 6
#define STATE__authRespCreated 7
#define STATE__verifyQueRespFailed 8
static pcap_t* devServer;
static char* tempDataServer;
static std::string tempDataServerStr;
class Server {
	private: 
	private:
		int hostId;
		int gateway;
		int server;
		int nonce;
		AuthReqMsg authReqMsg;
		AuthQueMsg authQueMsg;
		QueRespMsg queRespMsg;
		AuthRespMsg authRespMsg;
		int serverSk;
		int serverPk;
		int hostIp;
		int hostIdPk;
		Key hostIpSk;
		ByteVec secHostIpSk;
	public: 
		ByteVec SymEnc(ByteVec msg, int key);
		ByteVec Sign(ByteVec msg, int skey);
		bool Verify(ByteVec msg, int pkey);
		int receive(ByteVec msg);
		int send(ByteVec msg);
		void SMLMainServer();
};
static int __currentState = STATE___init;
int main(int argc, char** argv) {
	Server obj;
/*Initialize the object by user*/
	obj.SMLMainServer();
}
#endif

