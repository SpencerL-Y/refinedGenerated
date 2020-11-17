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
#include <ibe.h>
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

std::string SELF_IP_STR = "127.0.0.1";
std::string GATEWAY_IP_STR = "127.0.0.1";
u_short GATEWAY_IP_PORT = 6666;
u_short SELF_IP_PORT = 8888;

static pcap_t* devServer;
static char* tempDataServer;
static std::string tempDataServerStr;
class Server {
	private: 
	private:
		ByteVec msg;

		AcAuthReq_G2S acAuthReq_g2s;
		AuthQu authQu;
		AuthQuAck authQuAck;
		AuthRespMsg authRespMsg;
		AcAuthAns acAuthAns;
		ip_address client_id;
		ip_address gateway_id;
		ip_address server_id;
		int serverId_int;

        unsigned char master_privkey[IBE_MASTER_PRIVKEY_LEN];
        unsigned char master_pubkey[IBE_MASTER_PUBKEY_LEN];
        unsigned char usr_privkey[IBE_USR_PRIVKEY_LEN];
	public: 
		ByteVec SymEnc(ByteVec msg, int key);
		void Sign(unsigned char* msg, unsigned char* sig, size_t msglen);
		bool Verify(unsigned char* msg, unsigned char* sig, size_t msglen, int verify_id);
		int receive();
		int send(u_char* data_, int length_);
		void SMLMainServer();
		void initConfig();
};
static int __currentState = STATE___init;
int main(int argc, char** argv) {
	Server obj;
/*Initialize the object by user*/
	obj.SMLMainServer();
}
#endif

