#include "../generatedHeader/Alice.h"

static void dataHandlerAlice(u_char* param, const struct pcap_pkthdr* header, const u_char* packetData){
	ether_header* eh;
	eh = (ether_header*)packetData;
	if(ntohs(eh->type) == 0x888f){
		//TODO: refine the data structure
		std::cout << "ethernet frame received" << std::endl;
		int *length = (int*)((u_char*)packetData + sizeof(ether_header));
		int revert_length = ntohl(*length);
		int *id = (int*)((u_char*)packetData + sizeof(ether_header) + sizeof(int));
		int revert_id = ntohl(*id);
		char* data = (char*)((u_char*)packetData + sizeof(ether_header) + 2*sizeof(int));
		std::cout << "data received: " << data << std::endl;
		aliceTempData = (char*)malloc((revert_length - sizeof(int)));
		memcpy(aliceTempData, data, revert_length - sizeof(int));
		if(revert_id == 0x1){
			std::cout << "ethernet frame received end" << std::endl;
			pcap_breakloop(devAlice);
			return;
		}
	}
}

int Alice::receiveMsg(ByteVec &msg){
	/*Refine your Implementation here*/
	int length_ = 1000;
	u_char* data_ = (u_char*)malloc(length_*sizeof(u_char));
	u_char* dst_;	/*Add MAC Address here*/
	ushort mac[6];
	EtherReceiver er;
	pcap_if_t* dev = er.getDevice();

	char errbuf[500];
	pcap_t* selectedAdp = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
	devAlice = selectedAdp;
	/*Add self defined dataHandler to handle data received*/
	/*parameters: u_char* param, const struct pcap_pkthdr* header, const u_char* packetData*/
	u_char* packet = (u_char*)malloc(1000*sizeof(u_char));
	devAlice = selectedAdp;
	er.listenWithHandler(devAlice, dataHandlerAlice, data_);
	msg.content = aliceTempData;
	free(data_);
	int result;
	return result;

}
int Alice::sendMsg(ByteVec msg){
	/*Refine your Implementation here*/
	int length_ = 0;
	std::string sndA1Str = msg.content;
	u_char* data_ = (u_char*)sndA1Str.c_str();
	/*Add MAC Address here*/
	ushort mac[6];
	for(int i = 0;i < 6; i ++){
		mac[i] = 0x11;
	}
	EtherSender snd(mac);
	/*Add data and length to send*/
	int length = sndA1Str.size();
	snd.getDevice();
	std::cout << "send Broadcast" << std::endl;
	int success = snd.sendEtherBroadcast(data_, length, this->alice);
	std::cout << "send Broadcast End" << std::endl;
	int result;
	return result;

}
int Alice::sendPk(ByteVec msg){
	/*Add Ip Str and portNum here*/
	std::string IPStr_;
	u_short portNum_;
	UDPSender snd;
	/*Add length and data content here*/
	u_char* data_;
	int length_;
	snd.sendPacket(data_, length_, IPStr_, portNum_);
	int result;
	return result;

}
ByteVec Alice::SymEnc(Cryptor cryptor, ByteVec msg, char* key){
	ByteVec result;
	// serialize
	/*
	std::ostringstream os;
    boost::archive::binary_oarchive oa(os);
    oa << msg;
    */
	std::string content = mySerialize(msg);
	std::cout << "serialized data: "<< content << std::endl;
	std::cout << "Enckey: " <<  key << std::endl;
	char* cypher = (char*)malloc(1000*sizeof(char));
	memset(cypher, 0, 1000);
	cryptor.aes_encrypt((char *)content.c_str(), key, cypher);
	result.content = cypher;
	free(cypher);
	return result;

}
ByteVec Alice::SymDec(Cryptor cryptor, ByteVec msg, char* key){
	ByteVec result;
	char* decypher = (char*)malloc(1000*sizeof(char));
	memset(decypher, 0, 1000);
	std::cout << "encrypted received:" << msg.content << std::endl;
	std::cout << "DecKey: " << key << std::endl;
	cryptor.aes_decrypt((char *)msg.content.c_str(), key, decypher);
	std::cout << "decrypted: " << decypher << std::endl;
	// deserialize
	std::string content = decypher;
	result = myDeserialize(content);
	/*
	std::string decypher_content = decypher;
    std::istringstream is(decypher_content);
    boost::archive::binary_iarchive ia(is);
    ia >> result;
	*/
	free(decypher);
	return result;
}

