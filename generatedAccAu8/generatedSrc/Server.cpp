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
ByteVec Server::Sign(ByteVec msg, int skey){
Signature sig;
	memset(sig.sig,  0, 128);
	return sig;

}
bool Server::Verify(ByteVec msg, int pkey){
bool result = true;
	return result;

}
void Server::SMLMainServer(){
	while(__currentState != -100) {
		switch(__currentState){
			case STATE___init:{

				std::cout << "--------------------STATE___init" << std::endl;
				receive(authReqMsg);
				std::cout << "udp packet received" << std::endl;
				std::istringstream reqRecvedIs(tempDataServerStr);
				boost::archive::text_iarchive reqRecvedIA(reqRecvedIs);
				reqRecvedIA >> authReqMsg;
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
				if(!Verify(authRespMsg,hostIdPk)){
				__currentState = STATE__verifyReqFailed;
				}
				else if(Verify(authRespMsg,hostIdPk)){
					hostId = authReqMsg.host;
					authQueMsg.head.msgType = 4;
					authQueMsg.head.timeStamp.time = authReqMsg.head.timeStamp.time+1;
					authQueMsg.host = authReqMsg.host;
					authQueMsg.nonce = nonce;
					authQueMsg.server = server;
					authQueMsg.signature = Sign(authQueMsg,serverSk);
				__currentState = STATE__queCreated;
				}
			}
				
				break;
			case STATE__queCreated:
			{
				
					std::cout << "--------------------STATE__queCreated" << std::endl;
					SendStr queCreatedStr;
					std::ostringstream queCreatedOs;
					boost::archive::text_oarchive queCreatedOA(queCreatedOs);
					queCreatedOA << authQueMsg;
					queCreatedStr.data = queCreatedOs.str();
					std::cout << "queCreated: " << queCreatedStr.data << std::endl;
					send(queCreatedStr);
					
				__currentState = STATE__queSent;
			}
				
				break;
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

