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
        printf("cmd: ./server port\nexample: ./server 8000");
        return 0;
    }

    int sockfd, connfd, len;
    struct sockaddr_in serv_addr, cli;

    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        printf("Socket ERROR!\n");
        exit(-1);
    }
    
    // 指定IP和端口
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));
    // 绑定IP和端口 
    if ((bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) != 0)
    {
        printf("Bind ERROR\n");
        exit(-1);
    }


    // 监听端口
    if ((listen(sockfd, 5)) != 0)
    {
        printf("Listen ERROR!\n");
        exit(-1);
    }

    
    // 接收连接请求
    len = sizeof(cli);
    connfd = accept(sockfd, (struct sockaddr *)&cli, (socklen_t*)&len);
    if (connfd < 0)
    {
        printf("Accept ERROR!\n");
        exit(-1);
    }
    else
        printf("Connect successful! ...\n");
    
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
    read(sockfd, buf, sizeof(buf));
    mpz_set_str(key.p, buf + 3, 16); // 将p写入key.p

    // 用于防止中间人攻击
    mpz_t temp;
    mpz_init_set_str(temp, "123456789", 16);

    // 服务端选择秘密的随机数 c
    generate_pri_key(key.pri_key);
    
    // 服务端计算 [a^c mod p]
    mpz_powm(key.pub_key, key.g, key.pri_key,
             key.p);
    
    // 将服务端的 [a^c mod p] 发送给服务器端
    bzero(buf, MAX);
    memcpy(buf, "pub", 3);
    mpz_get_str(buf + 3, 16, key.pub_key);
    write(sockfd, buf, sizeof(buf));

    // 接收服务器的 [a^b mod p]
    bzero(buf, MAX);
    read(sockfd, buf, sizeof(buf));
    mpz_set_str(client_pub_key, buf + 3, 16);
    
    // 服务端根据DH协议，计算密钥 s = [a^bc mod p]
    mpz_powm(key.s, client_pub_key, key.pri_key,
             key.p);
    mpz_set(s, key.s);

    mpz_get_str((char*)key_str, 16, s); // 将dh_s写入key
    mpz_clears(key.p, key.g, key.pri_key,
               key.pub_key, key.s, client_pub_key, NULL);
    
    mpz_clear(s); // 清除s
}

// 客户端服务器发送接收加密的消息
void data_exchange(int sockfd, unsigned char key[])
{
    // 首先进行身份确认(预共享密钥)
    int flag = psk(sockfd);
    if (flag)
    {
        printf("Identification ERROR！\n");
        exit(1);
    }
    else
        printf("Identification PASS！\n\n");

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
        read(sockfd, text, sizeof(text));
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

        printf("The result of data decryption is: ");
        for (int i = 3; i < 35; ++i)
            printf("%c", text[i]);
        printf("\n");
        
        // 发送数据
        bzero(text + 3, 33);
        printf("please input: ");
        mygetline((char*)text+3, 33);
        
        // AES256加密
        char * cripher = aes.getPlainText((char*)text + 3, &retlen);
        for (int k = 0; k < retlen; k++)
        {
            text[3+k] = cripher[k];
        }
        text[3+retlen] = '\0';
        
        printf("The result of data encryption is: ");
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

int psk(int sockfd)
{
    AES aes;
    int flag = 1; // 若接收到的与发送的相同，则为0，否则为非0
    unsigned char ch[PSK_LEN + 3 + 1];
    unsigned char text[33];                                   // 保存客户端返回的密文
    unsigned char key[32] = "0a12541bc5a2d6890f2536ffccab2e"; // 预共享密钥
    
    // 密钥扩展，生成轮密钥
    aes.setCipherKey((char *)key, 32);
    memcpy(ch, "pub", 3);
    get_random_str(ch + 3); // 得到随机字符串

    printf("psk code: %s\n\n", ch + 3);

    write(sockfd, ch, sizeof(ch)); // 明文发送给客户端
    bzero(text, 33);
    read(sockfd, text, sizeof(text));
    printf("psk data from client:");
    for (int i = 0; i < 32; ++i)
        printf("%02x ", text[i]);
    printf("\n\n");
    int retlen;
    aes.getPlainText((char *)text+3, &retlen);
    printf("The result of data decryption is: %s\n\n", text + 3);
    // 比较前后字符串是否相同
    flag = strncmp((char *)ch + 3, (char *)text + 3, PSK_LEN);

    return flag;
}