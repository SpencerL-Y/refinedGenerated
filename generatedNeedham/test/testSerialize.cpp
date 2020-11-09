#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <string>
#include <string.h>
#include "../CryptoLib/include/Cryptor.hpp"
#include "../UserType.hpp"
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/map.hpp>
#include <boost/serialization/string.hpp>

class myclass {
    
    private:
    
    public:
        /*friend class boost::serialization::access;
	    template<class Archive>
	    void serialize(Archive & ar, const unsigned int version){
	    	ar& what;
	    }*/
        std::string what;
        int id;

        void setId(int id){
            this->id = id;
        }

        void setString(std::string str){
            this->what = str;
        }

        void printString(){
            std::cout << this->what << std::endl;
        }

        void printId(){
            std::cout << this->id <<std::endl;
        }
    
};

namespace boost{
    namespace serialization{
        template<class Archive>
        void serialize(Archive & ar, myclass & d, const unsigned int version){
            ar& d.what;
            ar& d.id;
        }

    }
}
/*
class myclassChild : public myclass{
    private:
        friend class boost::serialization::access;
	    template<class Archive>
	    void serialize(Archive & ar, const unsigned int version){
            ar& boost::serialization::base_object<myclass>(*this);
	    	ar& what;
	    }
};
*/
int main(){
    std::string key = "key";
    std::string key1 = "key";
    myclass myo;
    myo.setString("what the fuck");
    myo.setId(1234);
    std::ostringstream os;
    boost::archive::text_oarchive oa(os);
    oa << myo;
    std::string content = os.str();

    std::cout << content << std::endl;
    
    Cryptor cryptor;
    Cryptor cryptor2;
    char* out = (char*)malloc(1000*sizeof(char));
    memset(out, 0, content.size());
    memcpy(out, content.c_str(), content.size());
    cryptor.aes_encrypt((char*)content.c_str(), "key", out);
    std::cout << "out: " << out << std::endl;
    
    char* outout = (char*)malloc(1000*sizeof(char));
    
    memset(outout, 0, 1000);
    cryptor2.aes_decrypt(out, "key", outout);
    std::cout << "outout: " << outout << std::endl; 
    content = outout;
    myclass myo2;
    std::istringstream is(content);
    boost::archive::text_iarchive ia(is);
    ia >> myo2;
    myo2.printId();
    myo2.printString();
    free(out);
    free(outout);
    /*
    ByteVec bv1;
    bv1.id = 1;
    bv1.nonce = 10;
    bv1.nonce1 = 100;
    bv1.nonce2 = 1000;
    bv1.content = "what the fuck";
    
    std::string content = mySerialize(bv1);
    std::cout << "serialized data: " << content << std::endl;
    Cryptor cryptor;
    Cryptor cryptor2;
    char* out = (char*)malloc(content.size()*sizeof(char));
    memset(out, 0, content.size());
    memcpy(out, content.c_str(), content.size());
    cryptor.aes_encrypt((char*)content.c_str(), "key", out);
    std::cout << "out: " << out << std::endl;
    
    char* outout = (char*)malloc(1000*sizeof(char));
    
    memset(outout, 0, 1000);
    cryptor2.aes_decrypt(out, "key", outout);
    std::cout << "outout: " << outout << std::endl; 
    content = outout;
    myDeserialize(content);*/

}