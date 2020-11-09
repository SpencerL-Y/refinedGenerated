#ifndef Gateway_h
#define Gateway_h
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
#define STATE__reqMsgRecved 2
#define STATE__reqMsgSent 3
#define STATE__authQueRecved 4
#define STATE__authQueSent 5
#define STATE__queRespRecved 6
#define STATE__queRespSent 7
#define STATE__authRespRecved 8
static pcap_t* devGateway;
static char* tempDataGateway;
static std::string tempDataGatewayStr;
;class Gateway {
	private: 
	private:
		int hostId;
		int gateway;
		int server;
		ByteVec msg;
		int hostIdPk;
		int serverPk;
	public: 
		ByteVec Sign(ByteVec msg, int skey);
		bool Verify(ByteVec msg, int pkey);
		int recvFromHost(ByteVec msg);
		int sendToHost(ByteVec msg);
		int recvFromServer(ByteVec msg);
		int sendToServer(ByteVec msg);
		void SMLMainGateway();
};
static int __currentState = STATE___init;
int main(int argc, char** argv) {
	Gateway obj;
/*Initialize the object by user*/
	obj.SMLMainGateway();
}
#endif

