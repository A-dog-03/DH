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
        printf("使用方式: ./client 服务器IP 服务器端口\n例如: ./client 127.0.0.1 8888");
        return 0;
    }
    int sockfd, connfd;
    struct sockaddr_in serv_addr, cli;
    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        printf("套接字创建失败!\n");
        exit(1);
    }

    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    // 连接服务器
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("连接服务器失败!\n");
        exit(1);
    }
    else
        printf("成功连接服务器！!\n");
    
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
    printf("将生成大素数p并发送(回车继续)...\n");
    getchar();
    generate_p(key.p);
    gmp_printf("p = %Zd\n\n", key.p);
    mpz_set_ui(key.g, (unsigned long int)5); // base g = 5
    
    // 将p发送给服务器
    char buf[1024];
    bzero(buf, 1024);
    memcpy(buf, "pri", 3);
    mpz_get_str(buf + 3, 16, key.p);
    write(sockfd, buf, sizeof(buf));

    // 客户端选择秘密的随机数 b
    printf("即将生成客户端私钥与公钥（回车继续）...\n");
    getchar();
    generate_pri_key(key.pri_key);
    gmp_printf("客户端的私钥为%Zd\n\n", key.pri_key);

    // 客户端计算 [a^b mod p]
    mpz_powm(key.pub_key, key.g, key.pri_key,
             key.p);
    gmp_printf("客户端的公钥为%Zd\n\n", key.pub_key);
    
    // 接收服务器的 [a^c mod p]
    bzero(buf, 1024);
    printf("等待接收服务器的公钥, 并发送客户端公钥...\n\n");
    read(sockfd, buf, sizeof(buf));
    mpz_set_str(server_pub_key, buf + 3, 16); // 按16进制将buf传递给server_pub_key
    gmp_printf("服务器的公钥为%Zd\n\n", server_pub_key);

    // 将客户端的 [a^b mod p] 发送给服务器端
    bzero(buf, 1024);
    memcpy(buf, "pub", 3);
    mpz_get_str(buf + 3, 16, key.pub_key); // 按16进制将公钥传递给buf
    write(sockfd, buf, sizeof(buf));

    // 客户端根据DH协议，计算密钥 s = [a^bc mod p]
    printf("按下回车计算客户端经过DH协议得到的密钥...\n");
    getchar();
    mpz_powm(key.s, server_pub_key, key.pri_key,
             key.p);
    mpz_set(s, key.s); // 将密钥传递给s

    // 清除mpz_t变量
    mpz_clears(key.p, key.g, key.pri_key,
               key.pub_key, key.s, server_pub_key, NULL);

    mpz_get_str((char*)key_str, 16, s); // 将dh_s写入key
    mpz_clears(key.p, key.g, key.pri_key,
               key.pub_key, key.s, server_pub_key, NULL);
    
    
    gmp_printf("DH得出密钥为: %Zd\n\n", s);
    mpz_clear(s); // 清除s
}

// 客户端服务器发送接收加密后的消息
void data_exchange(int sockfd, unsigned char key[])
{
    // 预共享密钥
    psk(sockfd);

    // 接收数据的缓冲区
    unsigned char text[36];

    memcpy(text, "msg", 3); // 标识消息头

    // 创建aes对象完成加密任务
    AES aes;
    int retlen;
    // 密钥扩展，生成轮密钥
    aes.setCipherKey((char *)key, strlen((const char*)key));
    printf("初始化轮密钥完成！\n\n");
    // 循环接收消息
    while (1)
    {
        // 输入要发送的明文
        bzero(text + 3, 33);
        printf("要发送的明文: ");
        mygetline((char *) text+3, 33);
        
        // AES256加密
        char * cripher = aes.getPlainText((char *)text+3, &retlen);
        for (int k = 0; k < retlen; k++)
        {
            text[3+k] = cripher[k];
        }
        text[3+retlen] = '\0';
        
        printf("密文为:\n");
        for (int i = 3; i < 35; ++i)
            printf("%02x ", text[i]);
        printf("\n");
        
        // 发送密文
        write(sockfd, text, sizeof(text));
        printf("发送成功！\n等待服务器回复...\n");
        
        // 接收服务器发送的密文
        bzero(text + 3, 33);
        read(sockfd, text, sizeof(text));
        printf("服务器端发送的密文：\n");
        for (int i = 3; i < 35; ++i)
            printf("%02x ", text[i]);
        printf("\n");
        
        // AES256解密
        char * plain = aes.getCripherText((char *)text+3, &retlen);
        printf("解密后的明文：");
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

// 客户端psk
void psk(int sockfd)
{
    AES aes;
    unsigned char text[33];                                           // 存放接收到的密文
    unsigned char key[32] = "0a12541bc5a2d6890f2536ffccab2e";         // 预共享密钥
    aes.setCipherKey((char *)key, 32);                          
    bzero(text, 33);
    read(sockfd, text, sizeof(text));
    printf("psk字符串为: %s\n\n", text + 3);
    // 对字符串加密并返回给服务器
    int retlen;
    aes.getPlainText((char *)text+3, &retlen);
    printf("加密后的密文：");
    for (int i = 3; i < 35; ++i)
        printf("%02x ", text[i]);
    printf("\n\n");
    printf("回车将加密后的字符串返回给服务器...\n");
    getchar();
    write(sockfd, text, sizeof(text));
}
