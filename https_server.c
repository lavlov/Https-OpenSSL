#include <openssl/bio.h>  
#include <openssl/ssl.h>  
#include <openssl/err.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define SERVER_PORT 443
#define CA_CERT_FILE "server/ca.crt"
#define SERVER_CERT_FILE "server/server.crt"
#define SERVER_KEY_FILE "server/server.key"

SSL_CTX  *ssl_ctx_int();
SSL *client_ssl_init(SSL_CTX *ctx, int fd);
int bind_and_listen();

int main(int argc, char **argv)  
{  
    printf("Server Running at hppts://127.0.0.1/\n");

    int data_len;  
    struct sockaddr_in addr;   
    int listen_fd, accept_fd;  
    socklen_t len  = sizeof(addr);
    SSL_CTX *ctx = ssl_ctx_int();
    listen_fd = bind_and_listen();
    int times = 0;
    while(1){
        char recvbuf[1024] = {0};
        char sendbuf[1024] = {0};
       
        accept_fd = accept(listen_fd, (struct sockaddr *)&addr, &len);
        SSL *ssl = client_ssl_init(ctx, accept_fd);
        data_len = SSL_read(ssl,recvbuf, sizeof(recvbuf));  
        fprintf(stdout, "[%d] Get %d data:\n%s\n",times++, data_len, recvbuf);

        sprintf(sendbuf, "HTTP/1.0 200 OK\r\n\r\n<h1>hello ssl! [%d]</h1>", times);
        SSL_write(ssl, sendbuf, strlen(sendbuf));  
    
        SSL_free (ssl);  
        close(accept_fd);
    }
    SSL_CTX_free (ctx);  
    return 0;
}

SSL_CTX  *ssl_ctx_int(){
    SSLeay_add_ssl_algorithms();  
    OpenSSL_add_all_algorithms();  
    SSL_load_error_strings();  
    ERR_load_BIO_strings();  
    SSL_CTX *ctx = SSL_CTX_new (SSLv23_method());
    if(ctx == NULL){
        printf("SSL_CTX_new error!\n");
        exit(0);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);  
  
    if(!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL)){
        printf("SSL_CTX_load_verify_locations error!\n");
        ERR_print_errors_fp(stderr);
        exit(0);
    }

    if(SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM) <= 0){
        printf("SSL_CTX_use_certificate_file error!\n");
        ERR_print_errors_fp(stderr);
        exit(0);
    }

    if(SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_PEM) <= 0){
        printf("SSL_CTX_use_PrivateKey_file error!\n");
        ERR_print_errors_fp(stderr);
        exit(0);
    }

    if(!SSL_CTX_check_private_key(ctx)){
        printf("SSL_CTX_check_private_key error!\n");
        ERR_print_errors_fp(stderr);
        exit(0);
    }
    return ctx;
}

SSL *client_ssl_init(SSL_CTX *ctx, int fd)
{
    if (ctx == NULL){
        printf("The SSL_CTX is NULL\n");
        exit(0);
    }

    SSL *ssl = SSL_new (ctx);
    if(!ssl){
        printf("SSL_new error!\n");
        ERR_print_errors_fp(stderr);
        exit(0);
    }
    SSL_set_fd (ssl, fd); 
    if(SSL_accept (ssl) != 1){
        int icode = -1;
        ERR_print_errors_fp(stderr);
        int iret = SSL_get_error(ssl, icode);
        printf("SSL_accept error! code = %d, iret = %d\n", icode, iret);
    }

    return ssl;
}

int bind_and_listen()
{
    int listen_fd;
  
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if( listen_fd == -1 ){
        printf("socket error\n");
        exit(0);
    }
    int one = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        printf("setsockopt error\n");
        close(listen_fd);
    }
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(SERVER_PORT);

    if(bind(listen_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0 ){
        printf("Bind error\n");
        exit(0);
    }

    if(listen(listen_fd, 5) < 0){
        printf("listen error\n");
        exit(0);
    }

    return listen_fd;
}
