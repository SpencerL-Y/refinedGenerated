#include "../generatedHeader/Server.h"
int Server::receive(ByteVec msg){
	/*Add IP Str and portNUm here*/
	std::string IPStr_ = "192.168.43.52";
	u_short portNum_ = 6666;
	UDPReceiver  er;
	/*allocation for dst_ here*/
	if(tempDataServer != NULL){
		free(tempDataServer);
	}
	tempDataServer = (char*)malloc(1000*sizeof(char));
	int result = er.receivePacket((u_char*)tempDataServer, IPStr_, portNum_);
	auth_header* auth_hdr = (auth_header*)tempDataServer;
	if(auth_hdr->type == 0x10){
		memcpy(&acAuthReq_g2s, tempDataServer, sizeof(AcAuthReq_G2S));
	} else if(auth_hdr->type = 0x21){
		memcpy(&authQuAck, tempDataServer, sizeof(AuthQuAck));
	} else {

	}
	tempDataServerStr = tempDataServer;
	std::cout << "recv: "<< tempDataServerStr << std::endl;
	return result;

}
int Server::send(ByteVec msg){
	/*Add Ip Str and portNum here*/
	std::string IPStr_ = "192.168.43.52";
	u_short portNum_ = 8888;
	UDPSender snd;
	/*Add length and data content to send here*/
	u_char* data_ = (u_char*)malloc(msg.data.size()*sizeof(char));
	memcpy(data_, (u_char*)msg.getData().c_str(), msg.data.size());
	int length_ = msg.getData().size();
	snd.sendPacket(data_, length_, IPStr_, portNum_);
	std::cout << "udp send: " << data_ << std::endl;
	free(data_);
	int result;
	return result;
}

ByteVec Server::SymEnc(ByteVec msg, int key){
	ByteVec result;
	return result;
}

void Server::Sign(unsigned char* msg, unsigned char* sig, size_t msglen){
	//sig = malloc(IBE_SIG_LEN * sizeof(unsigned char));
	// if (digital_sign(msg, msglen, usr_privkey, sig) == -1) {
    //     printf("digital_sign failed\n");
    //     goto end;
    // }
}

bool Server::Verify(unsigned char* msg, unsigned char* sig, size_t msglen){
	return true;
	// return digital_verify(sig, msg, msglen, hostIp, master_pubkey);
}

void Server::SMLMainServer(){
	srand(NULL);
	while(__currentState != -100) {
		switch(__currentState){
			case STATE___init:{

				std::cout << "--------------------STATE___init" << std::endl;
				receive(msg);
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
				if(!Verify((unsigned char*)&acAuthReq_g2s, (unsigned char*)acAuthReq_g2s.gateway_signature, sizeof(AcAuthReq_G2S) - 16)){
					__currentState = STATE__verifyReqFailed;
				}
				else if(Verify((unsigned char*)&acAuthReq_g2s, (unsigned char*)acAuthReq_g2s.gateway_signature, sizeof(AcAuthReq_G2S) - 16)){
					client_id = acAuthReq_g2s.client_id;
					authQu.auth_hdr.length = htonl(sizeof(AuthQu) - sizeof(auth_header));
					authQu.auth_hdr.serial_num = acAuthReq_g2s.auth_hdr.serial_num;
					authQu.auth_hdr.timestamp = acAuthReq_g2s.auth_hdr.timestamp;
					authQu.auth_hdr.type = 0x20;
					authQu.auth_hdr.version = 1;
					authQu.client_id = acAuthReq_g2s.client_id;
					authQu.random_num_rs = rand(); 
					authQu.server_id.byte1 = 0; 
					authQu.server_id.byte2 = 0; 
					authQu.server_id.byte3 = 0; 
					Sign((unsigned char*)&authQu, (unsigned char*)&authQu.server_signature, sizeof(AuthQu) - 16);
				__currentState = STATE__queCreated;
				}
				break;
			}
				
			case STATE__queCreated:
			{
				
					std::cout << "--------------------STATE__queCreated" << std::endl;
					
					
					
					__currentState = STATE__queSent;

				
				break;
			}
			case STATE__verifyReqFailed:{
				std::cout << "--------------------STATE__verifyReqFailed" << std::endl;
				
				__currentState = STATE___final;
				
				break;}
			case STATE__queSent:{
				std::cout << "--------------------STATE__queSent" << std::endl;
				
					receive(queRespMsg);
				std::cout << "udp packet received" << std::endl;
				std::istringstream queSentIs(tempDataServerStr);
				boost::archive::text_iarchive queSentIA(queSentIs);
				queSentIA >> queRespMsg;
				__currentState = STATE__queRespRecved;
				
				break;}
			case STATE__queRespRecved:{
				std::cout << "--------------------STATE__queRespRecved" << std::endl;
				if(!Verify(queRespMsg,hostIdPk)||queRespMsg.nonce!=nonce){
				__currentState = STATE__verifyQueRespFailed;
				}
				else if(Verify(queRespMsg,hostIdPk)&&queRespMsg.nonce==nonce){
					authRespMsg.head.msgType = 3;
					authRespMsg.head.timeStamp.time = queRespMsg.head.timeStamp.time +1;
					authRespMsg.host = queRespMsg.host;
					authRespMsg.gateway = gateway;
					authRespMsg.hostIp = hostIp;
					secHostIpSk = SymEnc(hostIpSk,hostIdPk);
					authRespMsg.secHostIpSk = secHostIpSk;
					authRespMsg.server = server;
					authRespMsg.signature = Sign(authRespMsg,serverSk);
				__currentState = STATE__authRespCreated;
				}
				break;}
			case STATE__authRespCreated:{
				std::cout << "--------------------STATE__authRespCreated" << std::endl;
				
					send(queRespMsg);
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

