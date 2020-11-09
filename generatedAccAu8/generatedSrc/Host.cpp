#include "../generatedHeader/Host.h"
static void dataHandlerHostReceive(u_char* param, const struct pcap_pkthdr* header, const u_char* packetData){
	ether_header* eh;
	eh = (ether_header*)packetData;
	/*Configure your own protocol number of ethernet frame*/
	
	if(ntohs(eh->type) == 0x888f){
		auth_header* authHead = (auth_header*)((char*)packetData + sizeof(ether_header));
		u_short type_num = ntohs(authHead->type);
		if(type_num == 1){
			// broadcast
			std::cout << "client: broadcast received" << std::endl;
			if(tempDataHost != NULL){
				free(tempDataHost);
			}
			tempDataHost = (char*)malloc(sizeof(char) * sizeof(GwAnce));
			memcpy(tempDataHost, ((char*)packetData + sizeof(ether_header)),  sizeof(GwAnce));
			tempDataHostStr = tempDataHost;
			pcap_breakloop(devHost);
		} else if(type_num == 3){
			// response
			std::cout << "client: response received" << std::endl;
			if(tempDataHost != NULL){
				free(tempDataHost);
			}
			tempDataHost = (char*)malloc(sizeof(char)*sizeof(AcAuthAns));
			memcpy(tempDataHost, ((char*)packetData + sizeof(ether_header)), sizeof(AcAuthAns));
			tempDataHostStr = tempDataHost;
			pcap_breakloop(devHost);
		} else if(type_num == 4){
			// authentication
			std::cout << "client: authentication received" << std::endl;
			if(tempDataHost != NULL){
				free(tempDataHost);
			}
			tempDataHost = (char*)malloc(sizeof(char)*sizeof(AuthQu));
			memcpy(tempDataHost, ((char*)packetData + sizeof(ether_header)), sizeof(AuthQu));
			tempDataHostStr = tempDataHost;
			pcap_breakloop(devHost);
		}
		return;
	}
}
int Host::receive(){
	/*Configure your own implementation of length_*/
	int length_ = 0;
	u_char* data_ = (u_char*)malloc(length_*sizeof(u_char));
	u_char* dst_;	/*Add MAC Address here*/
	ushort mac[6];
	EtherReceiver er;
	pcap_if_t* dev = er.getDevice();
	char errbuf[500];
	pcap_t* selectedAdp = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
	devHost = selectedAdp;
	/*Add self defined dataHandler to handle data received*/
	/*parameters: u_char* param, const struct pcap_pkthdr* header, const u_char* packetData*/
	er.listenWithHandler(devHost, dataHandlerHostReceive, data_);
	/*Add your own data processing logic here*/
	free(data_);
	int result;
	return result;

}
int Host::send(ByteVec msg, u_short type_num, u_char dmac[6]){
	//2: request package
	//5: acknownledge
	/*Configure your own implementation of length_*/
	std::string data = msg.getData();

	u_char* data_ = (u_char*)malloc(data.size()*sizeof(u_char));
	memcpy(data_, data.c_str(), data.size());
	u_char mac[6];
	// set your client and gateway mac here
	// HEREEEEEEEEEEEEEEE
	for(int i = 0; i < 6; i++){
		mac[i] = 0x11;
	}
	EtherSender snd(mac);
	snd.getDevice();
	/*add your identifier of the sender*/
	std::cout << "send ether frame" << std::endl;
	int success =snd.sendEtherWithMac(data_, data.size(), dmac);
	free(data_);
	int result;
	return result;

}
ByteVec Host::SymEnc(ByteVec msg, int key){
ByteVec result;
	return result;

}
ByteVec Host::SymDec(ByteVec msg, int key){
ByteVec result;
	return result;

}
ByteVec Host::Sign(ByteVec msg, int skey){
	Signature sig;
	memset(sig.sig,  0, 128);
	return sig;

}
bool Host::Verify(char* encrypted, int pkey){
bool result;
	return true;

}

void Host::initConfig(){

}

void Host::SMLMainHost(){
	while(__currentState != -100) {
		switch(__currentState){
			case STATE___init:{
				std::cout << "--------------------STATE___init" << std::endl;
					std::cout << "client: GwAnce received" << std::endl;
					receive();
					memcpy(&gwAnce, tempDataHost, sizeof(GwAnce));
					acAuthReq_c2g.auth_hdr.length = htons(sizeof(AcAuthReq_C2G) - sizeof(auth_header));
					acAuthReq_c2g.auth_hdr.serial_num = htonl(ntohl(gwAnce.auth_hdr.serial_num));
					acAuthReq_c2g.auth_hdr.timestamp = gwAnce.auth_hdr.timestamp;
					acAuthReq_c2g.auth_hdr.type = 0x01;
					acAuthReq_c2g.auth_hdr.version = 1;
					//TODO: CONFIGURE THE CLIENT IP
					acAuthReq_c2g.client_id = 0;
					//TODO: CONFIGURE THE CLIENT MAC
					for(int i = 0; i < 6; i ++){
						acAuthReq_c2g.client_mac[i] = 0;
					}
					acAuthReq_c2g.gateway_id = gwAnce.gateway_id;
					//TODO: add sign here
					acAuthReq_c2g.client_signature = Sign();
				__currentState = STATE__reqMsgCreated;
				
				break;}
			case STATE___final:{
				__currentState = -100;
				std::cout << "--------------------STATE___final" << std::endl;
				break;}
			case STATE__reqMsgCreated:{
				std::cout << "--------------------STATE__reqMsgCreated" << std::endl;
					
					SendStr sendStr;
					char* sendData = (char*)malloc(sizeof(AcAuthReq_C2G) * sizeof(char));
					memcpy(sendData, &acAuthReq_c2g, sizeof(AcAuthReq_C2G));
					sendStr.data = sendData;
					free(sendData);
					std::cout << "send: " << sendStr.data << std::endl;
					// CONFIGURE THE DMAC BY HELLO PACKET
					u_char* dmac = gwAnce.gateway_mac;
					send(sendStr, 2, dmac);
				__currentState = STATE__reqSent;
				
				break;}
			case STATE__reqSent:{
				std::cout << "--------------------STATE__reqSent" << std::endl;
				
				receive();
				
				__currentState = STATE__queRecieved;
				
				break;}
			case STATE__queRecieved:{
				std::cout << "--------------------STATE__queRecieved" << std::endl;
				//TODO add verify here
				if(!Verify((char*)(&authQu.server_signature),serverPk)){
					__currentState = STATE__verifyAuthQueFailed;
				} else if(Verify((char*)(&authQu.server_signature),serverPk)){
					std::cout << "identity judgement" << std::endl;
					if(ntohl(authQu.client_id) != this->clientId){
						std::cout << "ERROR: receive client id error" << std::endl;
					}
					std::cout << "serial number consistency judgement" << std::endl;
					if(ntohl(authQu.auth_hdr.serial_num) != gwAnce.auth_hdr.serial_num){
						std::cout << "ERROR: serial_num inconsistent" << std::endl;
					}
					std::cout << "replay detection" << std::endl;
					random_number_rs = ntohl(authQu.random_num_rs);
					authQuAck.auth_hdr.length = htons(sizeof(AuthQuAck) - sizeof(auth_header));
					authQuAck.auth_hdr.serial_num = authQu.auth_hdr.serial_num;
					authQuAck.auth_hdr.timestamp = authQu.auth_hdr.timestamp;
					authQuAck.auth_hdr.type = 0x21;
					authQuAck.client_id = htonl(this->clientId);
					authQuAck.random_number_rs = htonl(this->random_number_rs);
					authQuAck.client_signature = Sign();
					__currentState = STATE__queRespCreated;
				}
				break;}
			case STATE__queRespCreated:{
				std::cout << "--------------------STATE__queRespCreated" << std::endl;
					SendStr sendStr;
					char* sendData = (char*)malloc(sizeof(AuthQuAck) * sizeof(char));
					memcpy(sendData, &authQuAck, sizeof(AuthQuAck));
					sendStr.data = sendData;
					// CONFIGURE THE MAC HERE
					u_char dmac[6];
					send(sendStr, 5, dmac);
				__currentState = STATE__queRespSent;
				
				break;
			}
			case STATE__verifyAuthQueFailed:{
				std::cout << "--------------------STATE__verifyAuthQueFailed" << std::endl;
				
				__currentState = STATE___final;
				
				break;}
			case STATE__queRespSent:{
				std::cout << "--------------------STATE__queRespSent" << std::endl;
				
					receive();
				__currentState = STATE__respRecved;
				
				break;}
			case STATE__respRecved:{
				std::cout << "--------------------STATE__respRecved" << std::endl;

				memcpy(&acAuthAns, tempDataHost, sizeof(AcAuthAns));
				//TODO: add verify
				if(Verify((char*)acAuthAns.server_signature,serverPk)){
					//hostIpSk = SymDec(authRespMsg.secHostIpSk,hostIdSk);
				__currentState = STATE___final;
				}
				else if(!Verify((char*)acAuthAns.server_signature,serverPk)){
				__currentState = STATE__verifyAuthRespFailed;
				}
				break;}
			case STATE__verifyAuthRespFailed:{
				std::cout << "--------------------STATE__verifyAuthRespFailed" << std::endl;
				
				__currentState = STATE___final;
				
				break;}
			default: break;
		}
	}
}

