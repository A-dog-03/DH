#include <stdio.h>
#include <string.h>
#include <gmp.h>

#define PSK_LEN 20 // psk模式随机生成字符串的长度

typedef struct
{
	mpz_t p;
	mpz_t g;
	mpz_t pri_key;
	mpz_t pub_key;
	mpz_t s; //g^(AB)
} DH_key;

typedef struct
{
	mpz_t p;
	mpz_t g;
	mpz_t pri_key; // 中间人的私钥
	mpz_t pub_key; // 中间人的公钥
	mpz_t key2server; // 与服务器通信的密钥
	mpz_t key2client; // 与客户端通信的密钥
} Middle_Key;

void get_random_int(mpz_t z, mp_bitcnt_t n); // 随机生成一个规定范围内的整数
void generate_pri_key(mpz_t a);
void get_random_str(unsigned char *ch);
void generate_p(mpz_t prime);
int check_prime(mpz_t prime);