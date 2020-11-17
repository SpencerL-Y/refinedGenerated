#include "../generatedHeader/Server.h"
int Server::receive(){
	/*Add IP Str and portNUm here*/
	std::string IPStr_ = SELF_IP_STR;
	u_short portNum_ = SELF_IP_PORT;
	UDPReceiver  er;
	/*allocation for dst_ here*/
	if(tempDataServer != NULL){
		free(tempDataServer);
	}
	tempDataServer = (char*)malloc(1000*sizeof(char));
	int result = er.receivePacket((u_char*)tempDataServer, IPStr_, portNum_);
	auth_header* auth_hdr = (auth_header*)tempDataServer;
	if(auth_hdr->type == 0x10){
		std::cout << "acAuthReq_g2s recv" << std::endl;
		memcpy(&acAuthReq_g2s, tempDataServer, sizeof(AcAuthReq_G2S));
	} else if(auth_hdr->type = 0x21){
		std::cout << "authQuAck recv" << std::endl;
		memcpy(&authQuAck, tempDataServer, sizeof(AuthQuAck));
		std::cout << "WATCH1: " << tempDataServer << std::endl;
	} else {
		std::cout << "SHOULD NOT BE HERE" << std::endl;
	}
	std::cout << "recv: "<< tempDataServer << std::endl;
	return result;

}
int Server::send(u_char* data_, int length_){
	/*Add Ip Str and portNum here*/
	std::string IPStr_ = GATEWAY_IP_STR;
	u_short portNum_ = GATEWAY_IP_PORT;
	UDPSender snd;
	/*Add length and data content to send here*/
	int result = snd.sendPacket(data_, length_, IPStr_, portNum_);
	std::cout << "udp send: " << data_ << std::endl;
	return result;
}

ByteVec Server::SymEnc(ByteVec msg, int key){
	ByteVec result;
	return result;
}

void Server::Sign(unsigned char* msg, unsigned char* sig, size_t msglen){
	if (digital_sign(msg, msglen, usr_privkey, sig) == -1) {
        printf("digital_sign failed\n");
    }
	std::cout << "sign over" << std::endl;
}

bool Server::Verify(unsigned char* msg, unsigned char* sig, size_t msglen, int verify_id){
	if(digital_verify(sig, msg, msglen, verify_id, master_pubkey) == -1){
		std::cout << "VERIFY FAILED !!!" << std::endl;
		return false;
	} else {
		std::cout << "VERIFY CORRECT..." << std::endl;
		return true;
	}
}

void Server::initConfig(){
	ibe_init();
	server_id.byte1 = 127;
	server_id.byte2 = 0;
	server_id.byte3 = 0;
	server_id.byte4 = 1;
	memcpy(&serverId_int, &server_id, sizeof(int));
	unsigned char mprik[IBE_MASTER_PRIVKEY_LEN] = {0x40, 0x8c, 0xe9, 0x67};
	unsigned char mpubk[IBE_MASTER_PUBKEY_LEN] = {0x31, 0x57, 0xcd, 0x29, 0xaf, 0x13, 0x83, 0xb7, 0x5e, 0xa0};
	memcpy(master_privkey, mprik, IBE_MASTER_PRIVKEY_LEN);
	memcpy(master_pubkey, mpubk, IBE_MASTER_PUBKEY_LEN);
	// if (masterkey_gen(master_privkey, master_pubkey) == -1) {
    //         printf("masterkey_gen failed\n");
    // }
	std::cout << "start user key gen" << std::endl;
    userkey_gen(serverId_int, master_privkey, usr_privkey);
	std::cout << "start user key over" << std::endl;
}

int Id2Int(ip_address ip){
	int result;
	memcpy(&result, &ip, sizeof(int));
	return result;
}


void Server::SMLMainServer(){
	srand(NULL);
	initConfig();
	while(__currentState != -100) {
		switch(__currentState){
			case STATE___init:{

				std::cout << "--------------------STATE___init" << std::endl;
				receive();
				std::cout << "udp packet received" << std::endl;
				__currentState = STATE__reqRecved;
				break;
			}
			case STATE___final:
			{
				__currentState = -100;
				std::cout << "--------------------STATE___final" << std::endl;
				break;
			}
			case STATE__reqRecved:
			{
				std::cout << "--------------------STATE__reqRecved" << std::endl;
				if(!Verify((unsigned char*)&acAuthReq_g2s, (unsigned char*)acAuthReq_g2s.gateway_signature, sizeof(AcAuthReq_G2S) - 16, Id2Int(acAuthReq_g2s.gateway_id))){
					__currentState = STATE__verifyReqFailed;
				}
				else {
					client_id = acAuthReq_g2s.client_id;
					authQu.auth_hdr.length = htonl(sizeof(AuthQu) - sizeof(auth_header));
					authQu.auth_hdr.serial_num = acAuthReq_g2s.auth_hdr.serial_num;
					authQu.auth_hdr.timestamp = acAuthReq_g2s.auth_hdr.timestamp;
					authQu.auth_hdr.type = 0x20;
					authQu.auth_hdr.version = 1;
					authQu.client_id = acAuthReq_g2s.client_id;
					authQu.random_num_rs = htonl(rand()); 
					authQu.server_id = server_id;
					
					Sign((unsigned char*)&authQu, authQu.server_signature, sizeof(AuthQu) - 16);
				__currentState = STATE__queCreated;
				}
				break;
			}
				
			case STATE__queCreated:
			{
				
					std::cout << "--------------------STATE__queCreated" << std::endl;
					if(tempDataServer != NULL){
						free(tempDataServer);
					}
					tempDataServer = (char*)malloc(sizeof(AuthQu));
					memcpy(tempDataServer, &authQu, sizeof(AuthQu));
					send((u_char*)tempDataServer, sizeof(AuthQu));
					__currentState = STATE__queSent;

				
				break;
			}
			case STATE__verifyReqFailed:{
				std::cout << "--------------------STATE__verifyReqFailed" << std::endl;
				
				__currentState = STATE___final;
				
				break;}
			case STATE__queSent:{
				std::cout << "--------------------STATE__queSent" << std::endl;
				
				receive();
				std::cout << "udp packet received" << std::endl;
				__currentState = STATE__queRespRecved;
				
				break;}
			case STATE__queRespRecved:{
				std::cout << "--------------------STATE__queRespRecved" << std::endl;

				if(!Verify((unsigned char*)&authQuAck, (unsigned char*)authQuAck.client_signature, sizeof(AuthQuAck) - 16, Id2Int(authQuAck.client_id))){
					__currentState = STATE__verifyQueRespFailed;
				}
				else {
					bool result = true;
					result &= authQuAck.auth_hdr.serial_num == authQu.auth_hdr.serial_num;
					result &= authQuAck.auth_hdr.type == 0x21;
					result &= authQuAck.auth_hdr.timestamp == authQu.auth_hdr.timestamp;
					result &= authQuAck.random_number_rs == authQu.random_num_rs;
					if(!result){
						std::cout << "Error: entries matching problem of authQuAck" << std::endl;
					}
					acAuthAns.auth_hdr.length = htonl(sizeof(AcAuthAns) - sizeof(auth_header));
					acAuthAns.auth_hdr.serial_num = authQuAck.auth_hdr.serial_num;
					acAuthAns.auth_hdr.timestamp = authQuAck.auth_hdr.timestamp;
					acAuthAns.auth_hdr.type =  0x11;
					acAuthAns.auth_hdr.version = 1;
					int resultInt = result;
					acAuthAns.client_id = authQuAck.client_id;
					acAuthAns.auth_result = htonl(resultInt);
					acAuthAns.authorization = htonl(0);
					acAuthAns.client_ip_and_mask[0] = authQuAck.client_id;
					acAuthAns.client_ip_and_mask[1].byte1 = 255;
					acAuthAns.client_ip_and_mask[1].byte2 = 255;
					acAuthAns.client_ip_and_mask[1].byte3 = 255;
					acAuthAns.client_ip_and_mask[1].byte4 = 0;
					acAuthAns.gateway_ip = acAuthReq_g2s.gateway_id;
					// TODO: set prikey here.
					acAuthAns.client_ip_prikey;
					acAuthAns.random_num_rs = htonl(rand());
					acAuthAns.server_id = server_id;
					Sign((unsigned char*)&acAuthAns, (unsigned char*)&acAuthAns.server_signature, sizeof(AcAuthAns) - 16);
				__currentState = STATE__authRespCreated;
				}
				break;}
			case STATE__authRespCreated:{
				std::cout << "--------------------STATE__authRespCreated" << std::endl;
				if(tempDataServer != NULL){
					free(tempDataServer);
				}
				tempDataServer = (char*)malloc(sizeof(AcAuthAns));
				memcpy(tempDataServer, &acAuthAns, sizeof(AcAuthAns));
				send((u_char*)tempDataServer, sizeof(AcAuthAns));
				__currentState = STATE___final;
				
				break;}
			case STATE__verifyQueRespFailed:{
				std::cout << "--------------------STATE__verifyQueRespFailed" << std::endl;
				
				__currentState = STATE___final;
				
				break;}
			default: break;
		}
	}
}

