#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <stdlib.h>
#include <stdio.h>
#include <istream>
#include <ostream>
#include <thread>
#include <stdlib.h>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>
#include "./CryptoLib/include/Cryptor.hpp"


class ByteVec{
	public:
		int id;
		int nonce;
		int nonce1;
		int nonce2;
		std::string content;

		ByteVec(){
			id = -1;
			nonce = 0;
			nonce1 = 0;
			nonce2 = 0;
			content = "default";
		}
		void print(){
			std::cout << id << ","<< nonce << ","<< nonce1 << "," << nonce2 << ","<< content << std::endl;
		}
	private:
};

static Cryptor ctor;
template<typename Out>
void split(const std::string &s, char delim, Out result) {
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}
static std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

static std::string mySerialize(const ByteVec& bv){
	std::string result;
	result += std::to_string(bv.id);
	result += ",";
	result += std::to_string(bv.nonce);
	result += ",";
	result += std::to_string(bv.nonce1);
	result += ",";
	result += std::to_string(bv.nonce2);
	result += ",";
	result += bv.content;
	return result;
}


static ByteVec myDeserialize(const std::string& str){
	ByteVec bv;
	std::vector<std::string> splitted = split(str, ',');
	bv.id = stoi(splitted[0]);
	bv.nonce = stoi(splitted[1]);
	bv.nonce1 = stoi(splitted[2]);
	bv.nonce2 = stoi(splitted[3]);
	bv.content = splitted[4];
	bv.print();
	return bv;
}




namespace boost{
    namespace serialization{
        template<class Archive>
        void serialize(Archive & ar, ByteVec & d, const unsigned int version){
            ar& d.id;
			ar& d.nonce;
			ar& d.nonce1;
			ar& d.nonce2;
			ar& d.content;
		}
    }
}

