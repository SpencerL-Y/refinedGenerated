#include "../generatedHeader/Host.h"
static void dataHandlerHostReceive(u_char* param, const struct pcap_pkthdr* header, const u_char* packetData){
	ether_header* eh;
	eh = (ether_header*)packetData;
	/*Configure your own prootcol number of ethernet frame*/

	if(ntohs(eh->type) == 0x888f){
		std::cout << "ETHER RECEIVED:" << std::endl;
		auth_header* authHead = (auth_header*)((char*)packetData + sizeof(ether_header));
		u_char type_num = authHead->type;
		std::cout << "version: " << (int) authHead->version << std::endl;
		std::cout << "type num: " << (int)type_num << std::endl;
		if(type_num == 0x01){
			// broadcast
			std::cout << "client: broadcast received" << std::endl;
			if(tempDataHost != NULL){
				free(tempDataHost);
			}
			tempDataHost = (char*)malloc(sizeof(char) * sizeof(GwAnce));
			memcpy(tempDataHost, ((char*)packetData + sizeof(ether_header)),  sizeof(GwAnce));
			pcap_breakloop(devHost);
		} else if(type_num == 0x11){
			// response
			std::cout << "client: response received" << std::endl;
			if(tempDataHost != NULL){
				free(tempDataHost);
			}
			tempDataHost = (char*)malloc(sizeof(char)*sizeof(AcAuthAns));
			memcpy(tempDataHost, ((char*)packetData + sizeof(ether_header)), sizeof(AcAuthAns));
			pcap_breakloop(devHost);
		} else if(type_num == 0x20){
			// authentication
			std::cout << "client: authQu received" << std::endl;
			if(tempDataHost != NULL){
				free(tempDataHost);
			}
			tempDataHost = (char*)malloc(sizeof(char)*sizeof(AuthQu));
			memcpy(tempDataHost, ((char*)packetData + sizeof(ether_header)), sizeof(AuthQu));
			pcap_breakloop(devHost);
		} else {
			std::cout << "client: ignored" << std::endl;
		}
	}
}
int Host::receive(){
	/*Configure your own implementation of length_*/
	int length_ = 0;
	u_char* data_ = (u_char*)malloc(length_*sizeof(u_char));
	u_char* dst_;	/*Add MAC Address here*/
	u_char mac[6];
	EtherReceiver er;
	pcap_if_t* dev = er.getDevice();
	char errbuf[500];
	pcap_t* selectedAdp = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
	devHost = selectedAdp;
	std::cout << dev->name << std::endl;
	/*Add self defined dataHandler to handle data received*/
	/*parameters: u_char* param, const struct pcap_pkthdr* header, const u_char* packetData*/
	er.listenWithHandler(devHost, dataHandlerHostReceive, data_);
	/*Add your own data processing logic here*/
	free(data_);
	int result;
	return result;

}
int Host::send(char* data_, int length, u_char dmac[6]){
	//2: request package
	//5: acknownledge
	/*Configure your own implementation of length_*/
	u_char mac[6];
	// set your client and gateway mac here
	// HEREEEEEEEEEEEEEEE
	mac[0] = 0x48;
	mac[1] = 0x2a;
	mac[2] = 0xe3;
	mac[3] = 0x60;
	mac[4] = 0x31;
	mac[5] = 0xfa;
	EtherSender snd(mac);
	snd.getDevice();
	/*add your identifier of the sender*/
	std::cout << "send ether frame" << std::endl;
	int success =snd.sendEtherWithMac((u_char*)data_, length, dmac);
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
void Host::Sign(unsigned char* msg, unsigned char* sig, size_t msglen){
	//sig = malloc(IBE_SIG_LEN * sizeof(unsigned char));
	// if (digital_sign(msg, msglen, usr_privkey, sig) == -1) {
    //     printf("digital_sign failed\n");
    //     goto end;
    // }
}

bool Host::Verify(unsigned char* msg, unsigned char* sig, size_t msglen){
	return true;
	//return digital_verify(sig, msg, msglen, hostIp, master_pubkey);
}

void Host::initConfig(){

}


bool Host::IPEqual(ip_address* ip1, ip_address* ip2){
		if(ip1->byte1 == ip2->byte1 &&
		   ip1->byte2 == ip2->byte2 &&
		   ip1->byte3 == ip2->byte3 &&
		   ip1->byte4 == ip2->byte4){
			   return true;
		} else {
			return false;
		}
}

void Host::SMLMainHost(){
	while(__currentState != -100) {
		switch(__currentState){
			case STATE___init:{
				std::cout << "--------------------STATE___init" << std::endl;
					receive();
					std::cout << "client: GwAnce received" << std::endl;
					memcpy(&gwAnce, tempDataHost, sizeof(GwAnce));
					acAuthReq_c2g.auth_hdr.length = htons(sizeof(AcAuthReq_C2G) - sizeof(auth_header));
					acAuthReq_c2g.auth_hdr.serial_num = htonl(ntohl(gwAnce.auth_hdr.serial_num));
					acAuthReq_c2g.auth_hdr.timestamp = gwAnce.auth_hdr.timestamp;
					acAuthReq_c2g.auth_hdr.type = 0x10;
					acAuthReq_c2g.auth_hdr.version = 1;
					//TODO: CONFIGURE THE CLIENT IP
					acAuthReq_c2g.client_id.byte1 = 127;
					acAuthReq_c2g.client_id.byte2 = 0;
					acAuthReq_c2g.client_id.byte3 = 0;
					acAuthReq_c2g.client_id.byte4 = 1;
					//TODO: CONFIGURE THE CLIENT MAC
					acAuthReq_c2g.client_mac[0] = 0x48;
					acAuthReq_c2g.client_mac[1] = 0x2a;
					acAuthReq_c2g.client_mac[2] = 0xe3;
					acAuthReq_c2g.client_mac[3] = 0x60;
					acAuthReq_c2g.client_mac[4] = 0x31;
					acAuthReq_c2g.client_mac[5] = 0xfa;
					
					acAuthReq_c2g.gateway_id = gwAnce.gateway_id;
					//TODO: add sign here
					Sign((unsigned char*)&acAuthReq_c2g, acAuthReq_c2g.client_signature, sizeof(AcAuthReq_C2G) - 16);
				__currentState = STATE__reqMsgCreated;
				
				break;}
			case STATE___final:{
				__currentState = -100;
				std::cout << "--------------------STATE___final" << std::endl;
				break;}
			case STATE__reqMsgCreated:{
				std::cout << "--------------------STATE__reqMsgCreated" << std::endl;
					
					char* sendData = (char*)malloc(sizeof(AcAuthReq_C2G) * sizeof(char));
					memcpy(sendData, &acAuthReq_c2g, sizeof(AcAuthReq_C2G));
					
					
					std::cout << "send: " << sendData << std::endl;
					// CONFIGURE THE DMAC BY HELLO PACKET
					u_char* dmac = gwAnce.gateway_mac;
					send(sendData, sizeof(AcAuthReq_C2G), dmac);
					free(sendData);
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
				if(!Verify((unsigned char*)&authQu, (unsigned char*)authQu.server_signature, sizeof(AuthQu) - 16)){
					__currentState = STATE__verifyAuthQueFailed;
				} else if(Verify((unsigned char*)&authQu, (unsigned char*)authQu.server_signature, sizeof(AuthQu) - 16)){
					std::cout << "identity judgement" << std::endl;
					if(!this->IPEqual(&authQu.client_id, &this->clientId)){
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
					authQuAck.client_id = this->clientId;
					authQuAck.random_number_rs = htonl(this->random_number_rs);
					Sign((unsigned char*)&authQuAck, (unsigned char*)&authQuAck.client_signature, sizeof(AuthQuAck) - 16);
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
					send(sendData, 5, dmac);
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
				if(Verify((unsigned char*)&acAuthAns, (unsigned char*)&acAuthAns.server_signature, sizeof(AcAuthAns) - 16)){
					//hostIpSk = SymDec(authRespMsg.secHostIpSk,hostIdSk);
					__currentState = STATE___final;
				}
				else if(!Verify((unsigned char*)&acAuthAns, (unsigned char*)&acAuthAns.server_signature, sizeof(AcAuthAns) - 16)){
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

