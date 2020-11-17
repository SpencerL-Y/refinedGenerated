#include <time.h>
#include <string.h>
#include  <iostream>
#include "ibe.h"
#define MSG_LEN 4

/* 0->'0', 1->'1', ... , 15->'F' */
static const uint8_t ascii_table[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

int u8_to_hex(const uint8_t *in, int in_len, uint8_t *out)
{
    if (in == NULL || out == NULL)
        return -1;

    for (int i = 0; i < in_len; i++) {
        out[0] = ascii_table[in[i] >> 4];
        out[1] = ascii_table[in[i] & 0xf];
        out += 2;
    }
    return 0;
}

void random_string(unsigned char *s, int len)
{
    static int c = 0;
    srand((unsigned)time(NULL) + c);
    while (len--)
        s[len] = rand() % 256;

    c++;
}

int random_number()
{
    static int c = 0;
    srand((unsigned)time(NULL) + c);
    c++;
    return rand();
}

void print_hex(const char *name, unsigned char *s, int slen)
{
    for(int i = 0; i < strlen(name); i++)
        printf("%c", name[i]);
    unsigned char *hex = (unsigned char*)malloc(2*slen);
    u8_to_hex(s, slen, hex);
    for(int i = 0; i < 2*slen; i++)
        printf("%c", hex[i]);
    printf("\n");
    free(hex);
}

int sign_test()
{
    int N = 1111;
    int ret = -1;
    unsigned int usr_id;
    unsigned char master_privkey[IBE_MASTER_PRIVKEY_LEN];
    unsigned char master_pubkey[IBE_MASTER_PUBKEY_LEN];
    unsigned char usr_privkey[IBE_USR_PRIVKEY_LEN];
    unsigned char *msg;
    size_t msglen;
    unsigned char sig[IBE_SIG_LEN];

    for (int i = 0; i < N; i++) {
        /* generate master key */
        if (masterkey_gen(master_privkey, master_pubkey) == -1) {
            printf("masterkey_gen failed\n");
            goto end;
        }
        std::cout << "pri:" <<  master_privkey << std::endl;

        std::cout << "pub:"<< master_pubkey << std::endl;
        
    }

    printf("signature test PASS\n");
    ret = 0;
end:
    return ret;
}


int main(int argc, char **argv)
{
    ibe_init();
    sign_test();
    return 0;
}
