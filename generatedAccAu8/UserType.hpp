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
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>
class Timer {
	public: 
		 int reset();
		 int time;
};
class ByteVec{
	public:
		std::string data;
		std::string getData(){
			return this->data;
		}
};
class Head{
	public:
		int version;
		int msgType;
		int seq;
		Timer timeStamp;
		int length;
};
class GwAdvMsg : public ByteVec{
	public:
		Head head;
		int gateway;
		int gwInfo;
		ByteVec signature;
};
class AuthReqMsg : public ByteVec{
	public:
		Head head;
		int host;
		int gateway;
		ByteVec signature;
};
class AuthQueMsg : public ByteVec{
	public:
		Head head;
		int host;
		int server;
		int gateway;
		ByteVec signature;
		int nonce;
};
class QueRespMsg : public ByteVec{
	public:
		Head head;
		int host;
		int nonce;
		ByteVec signature;
};
class AuthRespMsg : public ByteVec{
	public:
		Head head;
		int host;
		int result;
		int authority;
		int hostIp;
		int gateway;
		ByteVec secHostIpSk;
		int server;
		ByteVec signature;
};

class Signature : public ByteVec{
	public:
		char sig[128];

};

class Key : public ByteVec{
	public:
		int k;
};


class SendStr : public ByteVec{
	
};

namespace boost{
	namespace serialization{
		template<class Archive>
		void serialize(Archive& ar, Timer& d, const unsigned int version){
			ar& d.time;
		}
		template<class Archive>
		void serialize(Archive & ar, ByteVec & d, const unsigned int version){
		}
		template<class Archive>
		void serialize(Archive & ar, Head & d, const unsigned int version){
			ar& d.version;
			ar& d.msgType;
			ar& d.seq;
			ar& d.timeStamp;
			ar& d.length;
		}
		template<class Archive>
		void serialize(Archive & ar, GwAdvMsg & d, const unsigned int version){
			ar& d.head;
			ar& d.gateway;
			ar& d.gwInfo;
			ar& d.signature;
		}
		template<class Archive>
		void serialize(Archive & ar, AuthReqMsg & d, const unsigned int version){
			ar& d.head;
			ar& d.host;
			ar& d.gateway;
			ar& d.signature;
		}
		template<class Archive>
		void serialize(Archive & ar, AuthQueMsg & d, const unsigned int version){
			ar& d.head;
			ar& d.host;
			ar& d.server;
			ar& d.gateway;
			ar& d.signature;
			ar& d.nonce;
		}
		template<class Archive>
		void serialize(Archive & ar, QueRespMsg & d, const unsigned int version){
			ar& d.head;
			ar& d.host;
			ar& d.nonce;
			ar& d.signature;
		}
		template<class Archive>
		void serialize(Archive & ar, AuthRespMsg & d, const unsigned int version){
			ar& d.head;
			ar& d.host;
			ar& d.result;
			ar& d.authority;
			ar& d.hostIp;
			ar& d.gateway;
			ar& d.secHostIpSk;
			ar& d.server;
			ar& d.signature;
		}
		template<class Archive>
		void serialize(Archive & ar, Key & d, const unsigned int version){
			ar& d.k;
		}
	}
}

