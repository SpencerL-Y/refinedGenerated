import os
import sys
os.system("g++ -g -c CommLib/NetComm/src/*.cpp")
os.system("ar cqs libnetcomm.a ./*.o")
os.system("mv *.o CommLib/NetComm/src/")
os.system("mv *.a CommLib/NetComm/src/")
os.system("g++ -g -c CryptoLib/src/*.cpp")
os.system("ar cqs libcryptorlib.a ./*.o")
os.system("mv *.o CryptoLib/src/")
os.system("mv *.a CryptoLib/src/")
os.system("g++ -g -o Host ./generatedSrc/Host.cpp  -L./CommLib/NetComm/src/ -lnetcomm -L./CryptoLib/src/  -lcryptorlib -L./CryptoLib/src/ -lssl -lcrypto -lpcap -lboost_serialization  -libe -lpbc -lgmp -lpthread")
os.system("g++ -g -o Gateway ./generatedSrc/Gateway.cpp -L./CommLib/NetComm/src/ -lnetcomm -L./CryptoLib/src/ -lcryptorlib -L./CryptoLib/src/ -lssl -lcrypto -lpcap -lboost_serialization -libe -lpbc -lgmp -lpthread")
os.system("g++ -g -o Server ./generatedSrc/Server.cpp -L./CommLib/NetComm/src/ -lnetcomm -L./CryptoLib/src/ -lcryptorlib -L./CryptoLib/src/ -lssl -lcrypto -lpcap -lboost_serialization -libe -lpbc -lgmp -lpthread")
os.system("g++ -g -o test ./generatedSrc/test.cpp -L./CommLib/NetComm/src/ -lnetcomm -L./CryptoLib/src/ -lcryptorlib -lssl -lcrypto -lpcap -lboost_serialization -libe -lpbc -lgmp -lpthread")
