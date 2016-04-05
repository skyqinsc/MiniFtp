#ifndef _SYS_UTIL_H_
#define _SYS_UTIL_H_

#include "common.h"

int tcp_client(unsigned short port);
int tcp_server(const char *host, unsigned short port);

int getlocalip(char * ip); //获取本地IP

void activate_nonblock(int fd); //设置fd为非阻塞模式
void deactivate_nonblock(int fd); //fd去非阻塞模式

int read_timeout(int fd,unsigned int wait_seconds); // 读超时
int write_timeout(int fd,unsigned int wait_seconds); // 写超时
int accept_timeout(int fd,struct sockaddr_in *addr,unsigned int wait_seconds); // 接受连接超时
int connect_timeout(int fd,struct sockaddr_in *addr,unsigned int wait_seconds);  // 连接超时


ssize_t readn(int fd,void *buf,size_t count);
ssize_t writen(int fd, const void *buf ,size_t count);//
ssize_t recv_peek(int sockfd, void *buf,size_t len);
ssize_t readline(int sockfd,void* buf,size_t maxline);

void send_fd(int sock_fd,int fd); // 发送fd文件描述符
int recv_fd(const int sock_fd); // 接受文件描述符

const char * statbuf_get_perms(struct stat *sbuf);
const char *statbuf_get_date(struct stat *sbuf);

int lock_file_read(int fd);
int lock_file_write(int fd);
int unlock_file(int fd);

long get_time_sec();
long get_time_usec();

void nano_sleep(double sec);

void activate_obbinline(int fd);
void activate_sigurg(int fd);

#endif /* _SYS_UTIL_H_ */

