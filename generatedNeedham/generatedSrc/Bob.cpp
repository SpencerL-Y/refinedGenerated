#include "../generatedHeader/Bob.h"

static void dataHandlerBob(u_char* param, const struct pcap_pkthdr* header, const u_char* packetData){
	ether_header* eh;
	eh = (ether_header*)packetData;
	if(ntohs(eh->type) == 0x888f){
		//TODO: refine the data structure 
		std::cout << "ethernet frame received" << std::endl;
		int *length = (int*)((u_char*)packetData + sizeof(ether_header));
		int revert_length = ntohl(*length);
		std::cout << "length received" << std::endl;
		int *id = (int*)((u_char*)packetData + sizeof(ether_header) + sizeof(int));
		int revert_id = ntohl(*id);
		std::cout << "id received :" << revert_id << std::endl;
		char* data = (char*)((u_char*)packetData + sizeof(ether_header) + 2*sizeof(int));
		std::cout << "data received: " << data << std::endl;
		bobTempData = (char*)malloc((revert_length - sizeof(int)));
		memcpy(bobTempData, data, revert_length - sizeof(int));
		if(revert_id == 0x0){
			std::cout << "ethernet frame received end" << std::endl;	
			pcap_breakloop(devBob);
			return;
		}
	}
}
int Bob::receiveMsg(ByteVec& msg){
	/*Refine your Implementation here*/
	int length_ = 1000;
	u_char* data_ = (u_char*)malloc(length_*sizeof(u_char));
	u_char* dst_;	/*Add MAC Address here*/
	ushort mac[6];
	EtherReceiver er;
	pcap_if_t* dev = er.getDevice();
	char errbuf[500];
	pcap_t* selectedAdp = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
	/*Add self defined dataHandler to handle data received*/
	/*parameters: u_char* param, const struct pcap_pkthdr* header, const u_char* packetData*/	
	devBob = selectedAdp;
	er.listenWithHandler(devBob, dataHandlerBob, data_);
	msg.content = bobTempData;
	std::cout << "endloop data:" << msg.content << std::endl;
	free(data_);
	int result;
	return result;

}
int Bob::sendMsg(ByteVec msg){
	/*Refine your Implementation here*/
	int length_ = 0;
	std::string sndB1Str = msg.content;
	u_char* data_ = (u_char*)sndB1Str.c_str();
	ushort mac[6];
	for(int i = 0; i < 6; i ++){
		mac[i] = 0x22;
	}
	EtherSender snd(mac);
	/*Add data and length to send*/
	int length = sndB1Str.size();
	snd.getDevice();
	std::cout << "send Broadcast" << std::endl;
	int success = snd.sendEtherBroadcast(data_, length, this->bob);
	std::cout << "send Broadcast end" << std::endl;
	int result;
	return result;

}
int Bob::recvPk(ByteVec& msg){
	/*Add IP Str and portNUm here*/
	std::string IPStr_;
	u_short portNum_;
	UDPReceiver  er;
	/*allocation for dst_ here*/
	u_char* dst_;
	er.receivePacket(IPStr_, portNum_);
	int result;
	return result;
	
}

ByteVec Bob::SymEnc(Cryptor cryptor, ByteVec msg, char* key){
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

ByteVec Bob::SymDec(Cryptor cryptor, ByteVec msg, char* key){
	ByteVec result;
	char* decypher = (char*)malloc(1000*sizeof(char));
	memset(decypher, 0, 1000);
	std::cout << "encrypted received:" << msg.content << std::endl;
	std::cout << "DecKey: " << key << std::endl;
	cryptor.aes_decrypt((char *)msg.content.c_str(), key, decypher);
	std::cout << "decrypted: " << decypher << std::endl;
	std::string content = decypher;
	// deserialize
	std::cout << content << std::endl;
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

