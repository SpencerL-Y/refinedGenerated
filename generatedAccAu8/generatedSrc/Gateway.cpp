#include "../generatedHeader/Gateway.h"
static void dataHandlerGatewayrecvFromHost(u_char* param, const struct pcap_pkthdr* header, const u_char* packetData){
	ether_header* eh;
	eh = (ether_header*)packetData;
	/*Configure your own protocol number of ethernet frame*/
	if(ntohs(eh->type) == 0x888f){
		/*Add your own packet handling logic, tempData is used to store the packet after breaking the listening loop*/
		if(tempDataGateway != NULL){
			free(tempDataGateway);
		}
		auth_header* auth_hdr = (auth_header*)((char*)packetData + sizeof(ether_header));
		//TODO: PROBLEM HERE
		if(auth_hdr->type == 0x10 ){
			tempDataGateway = (char*)malloc(sizeof(AcAuthReq_C2G));
			memcpy(tempDataGateway, auth_hdr, sizeof(AcAuthReq_C2G));
			pcap_breakloop(devGateway);
		} else if(auth_hdr->type == 0x21){
			tempDataGateway = (char*)malloc(sizeof(AuthQuAck));
			memcpy(tempDataGateway, auth_hdr, sizeof(AuthQuAck));
			pcap_breakloop(devGateway);
		} else {

		}
		int breakingLoopCondition = 1;
		/*
		if(breakingLoopCondition){
			int* length = (int*)((char*)packetData + sizeof(ether_header));
			int converted_length = ntohl(*length);
			std::cout << "enter loop condition: length " << converted_length  << std::endl;
			if(tempDataGateway != NULL){
				free(tempDataGateway);
			}
			tempDataGateway = (char*)malloc(sizeof(char)*(converted_length));
			memcpy(tempDataGateway, ((char*)packetData + sizeof(ether_header) + sizeof(int)),  converted_length);
			std::cout << "loop break" << std::endl;
			tempDataGatewayStr = tempDataGateway;
			pcap_breakloop(devGateway);
			std::cout << "loop break over" << std::endl;
			return;
		}*/
	}
}
int Gateway::recvFromHost(){
	/*Configure your own implementation of length_*/
	int length_ = 1000;
	u_char* data_ = (u_char*)malloc(length_*sizeof(u_char));
	u_char* dst_;	/*Add MAC Address here*/
	EtherReceiver er;
	pcap_if_t* dev = er.getDevice();
	char errbuf[500];
	pcap_t* selectedAdp = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
	devGateway = selectedAdp;
	std::cout << dev->name << std::endl;
	/*Add self defined dataHandler to handle data received*/
	/*parameters: u_char* param, const struct pcap_pkthdr* header, const u_char* packetData*/
	er.listenWithHandler(devGateway, dataHandlerGatewayrecvFromHost, data_);
	/*Add your own data processing logic here*/
	free(data_);
	int result;
	return result;

}

int Gateway::sendToHost(u_char* data_, int length_){
	/*Configure your own implementation of length_*/
	std::cout << "send size: " << length_ << std::endl;
	//TODO: configure gateway mac
	u_char mac[6];
	mac[0] = 0x48;
	mac[1] = 0x2a;
	mac[2] = 0xe3;
	mac[3] = 0x60;
	mac[4] = 0x31;
	mac[5] = 0xfa;
	EtherSender snd(mac);
	snd.getDevice();
	/*add your identifier of the sender*/
	int result =snd.sendEtherBroadcast(data_, length_);
	return result;
}
int Gateway::recvFromServer(){
	/*Add IP Str and portNUm here*/
	std::string IPStr_ = SELF_IP_STR;
	u_short portNum_ = SELF_IP_PORT;
	UDPReceiver  er;
	/*allocation for dst_ here*/
	if(tempDataGateway != NULL){
		free(tempDataGateway);
	}
	tempDataGateway = (char*)malloc(1000*sizeof(char));
	int result = er.receivePacket((u_char*)tempDataGateway, IPStr_, portNum_);
	auth_header* auth_hdr = (auth_header*)tempDataGateway;
	if(auth_hdr->type == 0x20){
		memcpy(&authQu, tempDataGateway, sizeof(AuthQu));
	} else if(auth_hdr->type == 0x11){
		memcpy(&acAuthAns, tempDataGateway, sizeof(AcAuthAns));
	}
	std::cout << "udp recv: " << tempDataGateway << std::endl;
	return result;

}

int Gateway::sendToServer(){
	std::cout << "send to server" << std::endl;
	/*Add Ip Str and portNum here*/
	//TODO: add Server IP here
	std::string IPStr_ =  SERVER_IP_STR;
	u_short portNum_ = SERVER_IP_PORT;
	UDPSender snd;
	/*Add length and data content to send here*/
	
	auth_header* auth_hdr = (auth_header*)tempDataGateway;
	int length_ = 0;
	u_char* data_;
	if(auth_hdr->type == 0x10){

		AcAuthReq_C2G* old_packet = (AcAuthReq_C2G*)tempDataGateway;
		memcpy(&acAuthReq_c2g, tempDataGateway, sizeof(AcAuthReq_C2G));
		data_ = (u_char*)malloc(sizeof(AcAuthReq_G2S));
		AcAuthReq_G2S packet;
		packet.auth_hdr.length = htonl(sizeof(AcAuthReq_G2S) - sizeof(auth_header));
		packet.auth_hdr.serial_num = old_packet->auth_hdr.serial_num;
		packet.auth_hdr.timestamp = old_packet->auth_hdr.timestamp;
		packet.auth_hdr.serial_num = old_packet->auth_hdr.serial_num;
		packet.auth_hdr.type = old_packet->auth_hdr.type;
		packet.auth_hdr.version = old_packet->auth_hdr.version;
		packet.client_id = old_packet->client_id;
		memcpy(packet.client_mac, old_packet->client_mac, 6*sizeof(char));
		memcpy(packet.client_signature, old_packet->client_signature, 16*sizeof(char));
		packet.gateway_id = old_packet->gateway_id;
		packet.gateway_random_number = old_packet->gateway_random_number;
		Sign((unsigned char*)&packet.auth_hdr, (unsigned char*)&packet.gateway_signature, sizeof(AcAuthReq_G2S) - 16);
		length_ = sizeof(AcAuthReq_G2S);
		memcpy(data_, &packet, sizeof(AcAuthReq_G2S));
	} else if(auth_hdr->type = 0x21){
		memcpy(&this->authQuAck, tempDataGateway, sizeof(AuthQuAck));
		//test the validity TODO
		bool result = this->authQuAck.auth_hdr.serial_num == this->authQu.auth_hdr.serial_num;
		result &= this->authQuAck.auth_hdr.timestamp == this->authQu.auth_hdr.timestamp;
		result &= this->authQuAck.auth_hdr.type == 0x21;
		if(!result){
			std::cout << "error: info error" << std::endl;
		}
		data_ = (u_char*)malloc(sizeof(AuthQuAck));
		memcpy(data_, &this->authQuAck, sizeof(AuthQuAck));
	}

	std::cout << "send: " << tempDataGatewayStr << std::endl;
	int result = snd.sendPacket(data_, length_, IPStr_, portNum_);
	free(data_);
	return result;
}

void Gateway::Sign(unsigned char* msg, unsigned char* sig, size_t msglen){
	//sig = malloc(IBE_SIG_LEN * sizeof(unsigned char));
	// if (digital_sign(msg, msglen, usr_privkey, sig) == -1) {
    //     printf("digital_sign failed\n");
    //     goto end;
    // }
}

bool Gateway::Verify(unsigned char* msg, unsigned char* sig, size_t msglen){
	return true;
	// return digital_verify(sig, msg, msglen, hostIp, master_pubkey);
}

void Gateway::SMLMainGateway(){
	while(__currentState != -100) {
		switch(__currentState){
			case STATE___init:{
				std::cout << "--------------------STATE___init" << std::endl;
					
					gwAnce.auth_hdr.length = htonl(sizeof(GwAnce) - sizeof(auth_header));
					gwAnce.auth_hdr.serial_num = htonl(0);
					gwAnce.auth_hdr.timestamp = htonl(0);
					gwAnce.auth_hdr.type = 0x01;
					gwAnce.auth_hdr.version = 1;
					//TODO: configure gateway ip and mac here
					gwAnce.gateway_id.byte1 = 127;
					gwAnce.gateway_id.byte2 = 0;
					gwAnce.gateway_id.byte3 = 0;
					gwAnce.gateway_id.byte4 = 1;
					gwAnce.gateway_mac[0] = 0x48;
					gwAnce.gateway_mac[1] = 0x2a;
					gwAnce.gateway_mac[2] = 0xe3;
					gwAnce.gateway_mac[3] = 0x60;
					gwAnce.gateway_mac[4] = 0x31;
					gwAnce.gateway_mac[5] = 0xfa;
					//TODO: configure random number here
					gwAnce.gateway_random_number = htonl(rand());
					time_t t;
					time(&t);
					latest_time = t;
					gwAnce.auth_hdr.timestamp = htonl(t);
					//TODO: add memcpy here
					Sign((unsigned char*)&gwAnce, (unsigned char*)&gwAnce.signature, sizeof(GwAnce) - 16);
					char* output = (char*)&gwAnce;
					std::cout << sizeof(GwAnce) << std::endl;
					if(tempDataGateway != NULL){
						free(tempDataGateway);
					}
					tempDataGateway = (char*)malloc(sizeof(GwAnce));
					memcpy(tempDataGateway, &gwAnce, sizeof(GwAnce));
					GwAnce *gwa = (GwAnce*)tempDataGateway;
					auth_header* auth_hdr = (auth_header*)tempDataGateway;
					std::cout << "type: " << (int)gwAnce.auth_hdr.type << " : " << (int)auth_hdr->type << std::endl;
					std::cout << "tempDataGateway: " << tempDataGateway << std::endl;
					sendToHost((u_char*)tempDataGateway, sizeof(GwAnce));
					recvFromHost();
					memcpy(&acAuthReq_c2g, tempDataGateway, sizeof(AcAuthReq_C2G));
					
				__currentState = STATE__reqMsgRecved;
				
				break;}
			case STATE___final:{
				__currentState = -100;
				std::cout << "--------------------STATE___final" << std::endl;
				break;}
			case STATE__reqMsgRecved:{
				std::cout << "--------------------STATE__reqMsgRecved" << std::endl;

					sendToServer();
				__currentState = STATE__reqMsgSent;
				
				break;}
			case STATE__reqMsgSent:{
				std::cout << "--------------------STATE__reqMsgSent" << std::endl;
				
					recvFromServer();
				__currentState = STATE__authQueRecved;
				
				break;}
			case STATE__authQueRecved:{
				std::cout << "--------------------STATE__authQueRecved" << std::endl;
				
					sendToHost((u_char*)tempDataGateway, sizeof(AuthQu));
				__currentState = STATE__authQueSent;
				
				break;}
			case STATE__authQueSent:{
				std::cout << "--------------------STATE__authQueSent" << std::endl;
				
					recvFromHost();
				__currentState = STATE__queRespRecved;
				
				break;}
			case STATE__queRespRecved:{
				std::cout << "--------------------STATE__queRespRecved" << std::endl;
				
					sendToServer();
				__currentState = STATE__queRespSent;
				
				break;}
			case STATE__queRespSent:{
				std::cout << "--------------------STATE__queRespSent" << std::endl;
				
					recvFromServer();
				__currentState = STATE__authRespRecved;
				
				break;}
			case STATE__authRespRecved:{
				std::cout << "--------------------STATE__authRespRecved" << std::endl;
				
					sendToHost((u_char*)tempDataGateway, sizeof(AcAuthAns));
				__currentState = STATE___final;
				
				break;}
			default: break;
		}
	}
}

