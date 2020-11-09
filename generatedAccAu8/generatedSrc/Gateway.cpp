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
		if(auth_hdr->type == 0x10){
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
int Gateway::recvFromHost(ByteVec msg){
	/*Configure your own implementation of length_*/
	int length_ = sizeof(AcAuthReq_C2G);
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
	std::cout << "recv: " << tempDataGatewayStr << std::endl;
	free(data_);
	int result;
	return result;

}
int Gateway::sendToHost(ByteVec msg){
	/*Configure your own implementation of length_*/
	int length_ = tempDataGatewayStr.size();
	u_char* data_ = (u_char*)malloc(length_*sizeof(u_char));
	memcpy(data_, tempDataGatewayStr.c_str(), tempDataGatewayStr.size());
	//TODO: configure gateway mac
	u_char mac[6];
	EtherSender snd(mac);
	snd.getDevice();
	/*add your identifier of the sender*/
	int result =snd.sendEtherBroadcast(data_, length_);
	
	return result;

}
int Gateway::recvFromServer(ByteVec msg){
	/*Add IP Str and portNUm here*/
	std::string IPStr_ = "192.168.43.157";
	u_short portNum_ = 8888;
	UDPReceiver  er;
	/*allocation for dst_ here*/
	if(tempDataGateway != NULL){
		free(tempDataGateway);
	}
	tempDataGateway = (char*)malloc(1000*sizeof(char));
	int result = er.receivePacket((u_char*)tempDataGateway, IPStr_, portNum_);
	tempDataGatewayStr = tempDataGateway;
	std::cout << "udp recv: " << tempDataGatewayStr << std::endl;
	return result;

}
int Gateway::sendToServer(ByteVec msg){
	std::cout << "send to server" << std::endl;
	/*Add Ip Str and portNum here*/
	//TODO: add Server IP here
	std::string IPStr_ = "192.168.43.157";
	u_short portNum_ = 6666;
	UDPSender snd;
	/*Add length and data content to send here*/


	u_char* data_ = (u_char*)tempDataGatewayStr.c_str();
	int length_ = tempDataGatewayStr.size();

	std::cout << "send: " << tempDataGatewayStr << std::endl;
	int result = snd.sendPacket(data_, length_, IPStr_, portNum_);
	
	return result;
}

ByteVec Gateway::Sign(ByteVec msg, int skey){
Signature sig;
	memset(sig.sig,  0, 128);
	return sig;

}
bool Gateway::Verify(ByteVec msg, int pkey){
bool result;
	return result;

}
void Gateway::SMLMainGateway(){
	while(__currentState != -100) {
		switch(__currentState){
			case STATE___init:{
				std::cout << "--------------------STATE___init" << std::endl;
					if(tempDataGateway != NULL){
						free(tempDataGateway);
					}
					tempDataGateway = (char*)malloc(sizeof(GwAnce));
					GwAnce ancePacket;
					ancePacket.auth_hdr.length = htonl(sizeof(GwAnce) - sizeof(auth_header));
					ancePacket.auth_hdr.serial_num = htonl(0);
					ancePacket.auth_hdr.timestamp = htonl(0);
					ancePacket.auth_hdr.type = 0x01;
					ancePacket.auth_hdr.version = 1;
					//TODO: configure gateway ip and mac here
					ancePacket.gateway_id.byte1 = 255;
					ancePacket.gateway_id.byte2 = 255;
					ancePacket.gateway_id.byte3 = 255;
					ancePacket.gateway_id.byte4 = 255;
					ancePacket.gateway_mac[0] = 0x11;
					ancePacket.gateway_mac[1] = 0x11;
					ancePacket.gateway_mac[2] = 0x11;
					ancePacket.gateway_mac[3] = 0x11;
					ancePacket.gateway_mac[4] = 0x11;
					ancePacket.gateway_mac[5] = 0x11;
					ancePacket.gateway_mac[6] = 0x11;
					//TODO: configure random number here
					ancePacket.gateway_random_number = htonl(0);
					//TODO: add memcpy here
					char* sig = Sign();
					ancePacket.signature;

					sendToHost(msg);
					recvFromHost(msg);
				__currentState = STATE__reqMsgRecved;
				
				break;}
			case STATE___final:{
				__currentState = -100;
				std::cout << "--------------------STATE___final" << std::endl;
				break;}
			case STATE__reqMsgRecved:{
				std::cout << "--------------------STATE__reqMsgRecved" << std::endl;
				
					sendToServer(msg);
				__currentState = STATE__reqMsgSent;
				
				break;}
			case STATE__reqMsgSent:{
				std::cout << "--------------------STATE__reqMsgSent" << std::endl;
				
					recvFromServer(msg);
					msg.data = tempDataGatewayStr;
				__currentState = STATE__authQueRecved;
				
				break;}
			case STATE__authQueRecved:{
				std::cout << "--------------------STATE__authQueRecved" << std::endl;
				
					sendToHost(msg);
				__currentState = STATE__authQueSent;
				
				break;}
			case STATE__authQueSent:{
				std::cout << "--------------------STATE__authQueSent" << std::endl;
				
					recvFromHost(msg);
					msg.data = tempDataGateway;
				__currentState = STATE__queRespRecved;
				
				break;}
			case STATE__queRespRecved:{
				std::cout << "--------------------STATE__queRespRecved" << std::endl;
				
					sendToServer(msg);
				__currentState = STATE__queRespSent;
				
				break;}
			case STATE__queRespSent:{
				std::cout << "--------------------STATE__queRespSent" << std::endl;
				
					recvFromServer(msg);
				__currentState = STATE__authRespRecved;
				
				break;}
			case STATE__authRespRecved:{
				std::cout << "--------------------STATE__authRespRecved" << std::endl;
				
					sendToHost(msg);
				__currentState = STATE___final;
				
				break;}
			default: break;
		}
	}
}

