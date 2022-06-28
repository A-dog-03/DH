#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "../AES/aes.h"
#include "../Diffie_Hellman/DH.h"

#define MAX 1024

int mygetline(char str[], int lim);
void exchange_key(int sockfd, mpz_t s);
void data_exchange(int sockfd, unsigned char *key);
int psk(int sockfd);
void process(int connfd);

// 交互主函数 
int main(int argc, char **argv)
{
    // 接收命令行参数
    if (argc != 2)
    {
        printf("使用方式: ./server 监听端口\n例如: ./server 8008");
        return 0;
    }

    int sockfd, connfd, len;
    struct sockaddr_in serv_addr, cli;

    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        printf("套接字创建失败!\n");
        exit(-1);
    }
    else
        printf("套接字创建成功!");
    
    // 指定IP和端口
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));
    // 绑定IP和端口 
    if ((bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) != 0)
    {
        printf("绑定端口失败!\n");
        exit(-1);
    }
    else
		printf("端口绑定成功!\n");

    // 监听端口
    if ((listen(sockfd, 5)) != 0)
    {
        printf("监听端口失败!\n");
        exit(-1);
    }
    else
        printf("服务器监听中..\n"); 
    
    // 接收连接请求
    len = sizeof(cli);
    connfd = accept(sockfd, (struct sockaddr *)&cli, (socklen_t*)&len);
    if (connfd < 0)
    {
        printf("连接建立失败!\n");
        exit(-1);
    }
    else
        printf("接收到来自客户端的连接...\n");
    
    // 处理函数 
    process(connfd);

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
    DH_key key;
    mpz_t s;
    mpz_init(s);
    mpz_t client_pub_key; // 客户端公钥
    mpz_inits(key.p, key.g, key.pri_key,
              key.pub_key, key.s, client_pub_key, NULL);// 初始化mpz_t类型的变量
    mpz_set_ui(key.g, (unsigned long int)5); // g = 5
    
    // 从客户端接收p
    char buf[MAX];
    bzero(buf, MAX);
    printf("等待从客户端接收p...\n\n");
    read(sockfd, buf, sizeof(buf));
    mpz_set_str(key.p, buf + 3, 16); // 将p写入key.p
    gmp_printf("p = %Zd\n\n", key.p);

    // 用于防止中间人攻击
    mpz_t temp;
    mpz_init_set_str(temp, "123456789", 16);

    // 服务端选择秘密的随机数 c
    printf("将生成服务器端私钥与公钥(回车继续)...\n\n");
    generate_pri_key(key.pri_key);
    gmp_printf("服务器的私钥为%Zd\n\n", key.pri_key);
    
    // 服务端计算 [a^c mod p]
    mpz_powm(key.pub_key, key.g, key.pri_key,
             key.p);
    gmp_printf("服务器的公钥为%Zd\n\n", key.pub_key);

    // 将服务端的 [a^c mod p] 发送给服务器端
    bzero(buf, MAX);
    printf("按下回车发送公钥给客户端，并接收客户端公钥...\n");
    getchar();
    memcpy(buf, "pub", 3);
    mpz_get_str(buf + 3, 16, key.pub_key);
    write(sockfd, buf, sizeof(buf));

    // 接收服务器的 [a^b mod p]
    bzero(buf, MAX);
    read(sockfd, buf, sizeof(buf));
    mpz_set_str(client_pub_key, buf + 3, 16);
    gmp_printf("客户端公钥为%Zd\n\n", client_pub_key);

    // 服务端根据DH协议，计算密钥 s = [a^bc mod p]
    printf("按下回车计算服务器端经过DH协议得到的密钥...\n");
    getchar();
    mpz_powm(key.s, client_pub_key, key.pri_key,
             key.p);
    mpz_set(s, key.s);

    mpz_get_str((char*)key_str, 16, s); // 将dh_s写入key
    mpz_clears(key.p, key.g, key.pri_key,
               key.pub_key, key.s, client_pub_key, NULL);
    
    
    gmp_printf("DH得出密钥为: %Zd\n\n", s);
    mpz_clear(s); // 清除s
}

// 客户端服务器发送接收加密的消息
void data_exchange(int sockfd, unsigned char key[])
{
    // 用于接收数据缓冲区
    unsigned char text[36];

    memcpy(text, "msg", 3); // 标识消息头

    // 创建aes对象完成加密任务
    AES aes;
    int retlen;
    //密钥扩展，生成轮密钥
    aes.setCipherKey((char *)key, strlen((const char*)key));
    
    while (1)
    {
        bzero(text + 3, 33);
        
        // 接收数据
        printf("等待客户端发送消息...\n");
        read(sockfd, text, sizeof(text));
        printf("客户端发送的密文：\n");
        for (int i = 3; i < 35; ++i)
            printf("%02x ", text[i]);
        printf("\n");
        
        // AES256解密密文
        char * plain = aes.getCripherText((char*)text+3, &retlen);
        for (int k = 0; k < retlen; k++)
        {
            text[3+k] = plain[k];
        }
        text[3+retlen] = '\0';

        printf("解密后的明文: ");
        for (int i = 3; i < 35; ++i)
            printf("%c", text[i]);
        printf("\n");
        
        // 发送数据
        bzero(text + 3, 33);
        printf("要发送的消息: ");
        mygetline((char*)text+3, 33);
        
        // AES256加密
        char * cripher = aes.getPlainText((char*)text + 3, &retlen);
        for (int k = 0; k < retlen; k++)
        {
            text[3+k] = cripher[k];
        }
        text[3+retlen] = '\0';
        
        printf("密文为：");
        for (int i = 3; i < 35; ++i)
            printf("%02x ", text[i]);
        // 发送给客户端
        write(sockfd, text, sizeof(text));
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

