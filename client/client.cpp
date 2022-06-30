#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "../AES/aes.h"
#include "../Diffie_Hellman/DH.h"

int mygetline(char str[], int lim);
void exchange_key(int sockfd, mpz_t s);
void data_exchange(int sockfd, unsigned char *key);
void psk(int sockfd);

void process(int connfd);

// 主函数
int main(int argc, char **argv)
{
    if (argc != 3)
    {
        printf("cmd: ./client IP:Port\n example: ./client 192.168.17.147 8000");
        return 0;
    }
    int sockfd, connfd;
    struct sockaddr_in serv_addr, cli;
    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        printf("Socket ERROR!\n");
        exit(1);
    }

    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    // 连接服务器
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("Failed to connect to server!\n");
        exit(1);
    }
    else
        printf("Connecting to the server successfully!\n");

    // 处理函数
    process(sockfd);

    close(sockfd);
    return 0;
}

// 主处理函数
void process(int connfd)
{
    // 将密钥保存为unsigned char数组类型
    unsigned char key[32];
    // 根据DH协议交换信息计算密钥
    exchange_key(connfd, key);
    // 客户端服务器使用密钥通信
    data_exchange(connfd, key);
}

// 通过Diffie Hellman协议商讨出一个密钥s
// 公开参数：p,a,n
// a^b mod p
// a^c mod p
// key = a^bc mod p
void exchange_key(int sockfd, unsigned char * key_str)
{
    DH_key key; // 客户端生成的密钥
    mpz_t s;
    mpz_init(s);
    mpz_t server_pub_key; // 服务器公钥
    mpz_inits(key.p, key.g, key.pri_key,
              key.pub_key, key.s, server_pub_key, NULL);// 初始化mpz_t类型的变量
    
    // 由客户端生成 p 并以明文形式发送给服务器端
    generate_p(key.p);
    mpz_set_ui(key.g, (unsigned long int)5); // base g = 5
    
    // 将p发送给服务器
    char buf[1024];
    bzero(buf, 1024);
    memcpy(buf, "pri", 3);
    mpz_get_str(buf + 3, 16, key.p);
    write(sockfd, buf, sizeof(buf));

    // 客户端选择秘密的随机数 b
    generate_pri_key(key.pri_key);
    
    // 客户端计算 [a^b mod p]
    mpz_powm(key.pub_key, key.g, key.pri_key,
             key.p);
    
    // 接收服务器的 [a^c mod p]
    bzero(buf, 1024);
    read(sockfd, buf, sizeof(buf));
    mpz_set_str(server_pub_key, buf + 3, 16); // 按16进制将buf传递给server_pub_key
    
    // 将客户端的 [a^b mod p] 发送给服务器端
    bzero(buf, 1024);
    memcpy(buf, "pub", 3);
    mpz_get_str(buf + 3, 16, key.pub_key); // 按16进制将公钥传递给buf
    write(sockfd, buf, sizeof(buf));

    // 客户端根据DH协议，计算密钥 s = [a^bc mod p]
    mpz_powm(key.s, server_pub_key, key.pri_key,
             key.p);
    mpz_set(s, key.s); // 将密钥传递给s

    // 清除mpz_t变量
    mpz_clears(key.p, key.g, key.pri_key,
               key.pub_key, key.s, server_pub_key, NULL);

    mpz_get_str((char*)key_str, 16, s); // 将dh_s写入key
    mpz_clears(key.p, key.g, key.pri_key,
               key.pub_key, key.s, server_pub_key, NULL);
    
    
    gmp_printf("key: %Zd\n\n", s);
    mpz_clear(s); // 清除s
}

// 客户端服务器发送接收加密后的消息
void data_exchange(int sockfd, unsigned char key[])
{
    // 接收数据的缓冲区
    unsigned char text[36];

    memcpy(text, "msg", 3); // 标识消息头

    // 创建aes对象完成加密任务
    AES aes;
    int retlen;
    // 密钥扩展，生成轮密钥
    aes.setCipherKey((char *)key, strlen((const char*)key));
    // 循环接收消息
    while (1)
    {
        // 输入要发送的明文
        bzero(text + 3, 33);
        printf("Please input: ");
        mygetline((char *) text+3, 33);
        
        // AES256加密
        char * cripher = aes.getPlainText((char *)text+3, &retlen);
        for (int k = 0; k < retlen; k++)
        {
            text[3+k] = cripher[k];
        }
        text[3+retlen] = '\0';
        
        printf("The result of data encryption is:\n");
        for (int i = 3; i < 35; ++i)
            printf("%02x ", text[i]);
        printf("\n");
        
        // 发送密文
        write(sockfd, text, sizeof(text));
        printf("Send successful！\n");
        
        // 接收服务器发送的密文
        bzero(text + 3, 33);
        read(sockfd, text, sizeof(text));
        printf("Receive from the server:\n");
        for (int i = 3; i < 35; ++i)
            printf("%02x ", text[i]);
        printf("\n");
        
        // AES256解密
        char * plain = aes.getCripherText((char *)text+3, &retlen);
        printf("The result of data decryption is:");
        for (int i = 3; i < 35; ++i)
            printf("%c", text[i]);
        printf("\n\n\n");
    }
}

// 读取需要发送的消息
int mygetline(char str[], int lim) 
{ 
   char c;
   int i;
   for (i = 0; i < lim - 1 && ( (c = getchar()) != EOF && c != '\n'); ++i) {
      str[i] = c;
   }
   if (c == '\n') {
      str[i] = c;
   }
   str[++i] = '\0'; // 添加结束符
   return i;
}
