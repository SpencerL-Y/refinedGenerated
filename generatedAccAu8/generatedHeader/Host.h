#ifndef Host_h
#define Host_h
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
#include "../CommLib/NetComm/include/packet.hpp"
#define STATE___init 0
#define STATE___final 1
#define STATE__reqMsgCreated 2
#define STATE__reqSent 3
#define STATE__queRecieved 4
#define STATE__queRespCreated 5
#define STATE__verifyAuthQueFailed 6
#define STATE__queRespSent 7
#define STATE__respRecved 8
#define STATE__verifyAuthRespFailed 9
static pcap_t* devHost;
static char* tempDataHost;
static std::string tempDataHostStr;
class Host {
	private:
		// new version attributes
		int random_number_rs;
		GwAnce gwAnce;
		AcAuthReq_C2G acAuthReq_c2g;
		AuthQu authQu;
		AuthQuAck authQuAck;
		AcAuthAns acAuthAns;
		
		// client id;
		int clientId;
		
	public: 
		ByteVec SymEnc(ByteVec msg, int key);
		ByteVec SymDec(ByteVec msg, int key);
		ByteVec Sign(ByteVec msg, int skey);
		bool Verify(char* encrypted, int pkey);
		int receive();
		int send(ByteVec msg, u_short type_num, u_char dmac[6]);
		void SMLMainHost();
		void initConfig();
};
static int __currentState = STATE___init;
int main(int argc, char** argv) {
	Host obj;
/*Initialize the object by user*/
	obj.SMLMainHost();
}
#endif
