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

