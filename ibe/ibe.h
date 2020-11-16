#pragma once

#include "pbc/pbc.h"
#include "pbc/pbc_a_param.h"

#ifdef  __cplusplus
extern "C" {
#endif

extern pairing_t pairing;
/* G1 生成元 */
extern char *P_str;
extern element_t P;

extern int initialized;

#define EXPORT_API __attribute__ ((visibility ("default")))

#define IBE_MASTER_PRIVKEY_LEN  8 // 7,  actually
#define IBE_MASTER_PUBKEY_LEN  16 // 14, actually
#define IBE_USR_PRIVKEY_LEN    16 // 14, actually

#define IBE_SIG_LEN 16
#define IBE_MAC_LEN 16

/* 初始化曲线参数，必须在使用其他接口前调用一次 */
EXPORT_API int ibe_init();

/* 生成主密钥对 */
EXPORT_API int masterkey_gen(unsigned char *master_privkey, unsigned char *master_pubkey);

/* 生成用户私钥 */
EXPORT_API int userkey_gen(unsigned int usr_id, unsigned char *master_privkey, unsigned char *usr_privkey);

/* 使用用户私钥对消息签名 */
EXPORT_API int digital_sign(unsigned char *msg, unsigned short msg_len, unsigned char *usr_privkey, unsigned char *ds);

/* 使用用户ID和主公钥验证签名 */
EXPORT_API int digital_verify(unsigned char *ds, unsigned char *msg, unsigned short msg_len, unsigned int usr_id, unsigned char *master_pubkey);

/* 发送方使用发送方私钥(usr_privkey)为接收方(usr_id)计算消息认证码 */
EXPORT_API int mac_gen(unsigned int usr_id, unsigned char *msg, unsigned short msg_len, unsigned char *usr_privkey, unsigned char *mac);

/* 接收方使用接收方私钥(usr_privkey)验证发送方(usr_id)为他计算的消息认证码 */
EXPORT_API int mac_verify(unsigned int usr_id, unsigned char *msg, unsigned short msg_len, unsigned char *usr_privkey, unsigned char *mac);

#ifdef  __cplusplus
}
#endif





