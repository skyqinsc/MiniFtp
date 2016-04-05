#include"sysutil.h"

int tcp_client(unsigned short port){
	int sock;
	if((sock = socket(PF_INET,SOCK_STREAM,0))<0)
		ERR_EXIT("tcp_client");
	if(port > 0){
		int on =1;
		if((setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(const char *)&on,sizeof(on)))<0)
			ERR_EXIT("setsockopt");
		char ip[16] = {0};
		getlocalip(ip);
		struct sockaddr_in localaddr;
		memset(&localaddr, 0, sizeof localaddr);
		localaddr.sin_family = AF_INET;
		localaddr.sin_port = htons(port);
		localaddr.sin_addr.s_addr = inet_addr(ip);
		if(bind(sock,(struct sockaddr *)&localaddr,sizeof(localaddr))<0)
			ERR_EXIT("bind");
	}
	return sock;
}



/**
*tcp_server ->用来启动一个tcp服务器 
*@host :->服务器的ip或者主机名
*@port ：->服务器端口号
*成功返回监听套接字
*/


int tcp_server(const char *host,unsigned short port)
{
	int listenfd;
	if((listenfd = socket(PF_INET,SOCK_STREAM,0))<0)
		ERR_EXIT("tcp_server");
	struct sockaddr_in servaddr;
	bzero(&servaddr,sizeof servaddr);
	servaddr.sin_family = AF_INET;
    if(host != NULL)
    {
        if(inet_aton(host,&servaddr.sin_addr) ==0 )
        {
            struct hostent *hp;
			hp = gethostbyname(host);
            if(hp==NULL)
				ERR_EXIT("gethostbyname");
			servaddr.sin_addr=*(struct in_addr*)(hp->h_addr);
        }
	}
	else
		servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);
	int on =1;
	
	if((setsockopt(listenfd,SOL_SOCKET,SO_REUSEADDR,(const char *)&on,sizeof(on)))<0)
		ERR_EXIT("setsockopt");

	if(bind(listenfd,(struct sockaddr *)&servaddr,sizeof(servaddr))<0)
	{
		ERR_EXIT("bind");
	}
	if(listen(listenfd,SOMAXCONN)<0)
		ERR_EXIT("listen");
	return listenfd;

}
ssize_t readn(int fd,void *buf,size_t count)
{
    size_t nleft =count;
    ssize_t nread;
    char *bufp=(char *)buf;
    while(nleft>0)
    {
        if((nread=read(fd,bufp,nleft))<0)
        {
            if(errno == EINTR)
                continue;
            return -1;
        }
        else if(nread== 0)
            return count - nleft;
        bufp+=nread;
        nleft-=nread;
    }
    return count;
}

ssize_t writen(int fd,const void *buf,size_t count)
{
    
    size_t nleft =count;
    ssize_t nwritten;
    char *bufp=(char *)buf;

    while(nleft>0)
    {
        if((nwritten=write(fd,bufp,nleft))<0)
        {
            if(errno == EINTR)
                continue;
            return -1;
        }
        else if(nwritten== 0)
            continue;
        bufp+=nwritten;
        nleft-=nwritten;
    }
    return count;
}
ssize_t recv_peek(int sockfd,void *buf,size_t len)
{
    while(1)
    {
        int ret = recv(sockfd,buf,len,MSG_PEEK);
        if(ret== -1 && errno == EINTR)
            continue;
        return ret;
    }
}

ssize_t readline(int sockfd,void *buf, size_t maxline)
{
    int ret ;
    int nread;
    char *bufp= (char *)buf;
    int nleft = maxline;
    while(1)
    {
        ret = recv_peek(sockfd,bufp,nleft);
        if(ret<0)
            return ret ;
        else if (ret == 0)
            return ret ;
        nread = ret ;
        int i;
        for(i=0;i<nread;i++)
        {
            if(bufp[i]=='\n')
            {
                ret = readn(sockfd,bufp, i+1);
                if(ret != i+1)
                    exit(1);
                return ret;
            }
        }
        if(nread > nleft)
            exit(1);
        nleft-=nread;
        ret= readn(sockfd,bufp,nread);
        if(ret!= nread)
            exit(1);
        bufp+=nread;
    }
    return -1;
}
int getlocalip(char *ip)
{
    char host[100]={0};
    if (gethostname(host,sizeof(host))<0)
        ERR_EXIT("gethostname");
	printf("client is getting hostname: %s\n",host);
    struct hostent *hp;
    if((hp= gethostbyname(host))==NULL)
        return -1;
    strcpy(ip, inet_ntoa(*(struct in_addr *)hp->h_addr));
    return 0;
}


int connect_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds)
{
	int ret;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	if (wait_seconds > 0)
		activate_nonblock(fd);
	ret = connect(fd, (struct sockaddr*)addr, addrlen);
	if (ret < 0 && errno == EINPROGRESS)
	{
		fd_set connect_fdset;
		struct timeval timeout;
		FD_ZERO(&connect_fdset);
		FD_SET(fd, &connect_fdset);
		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		do
		{
			ret = select(fd + 1, NULL, &connect_fdset, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);
		if (ret == 0)
		{
			ret = -1;
			errno = ETIMEDOUT;
		}
		else if (ret < 0) return -1;
		else if (ret == 1){
			int err;
			socklen_t socklen = sizeof(err);
			int sockoptret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &socklen);
			if (sockoptret == -1) return -1;
			if (err == 0) ret = 0;
			else{
				errno = err;
				ret = -1;
			}
		}
	}
	if (wait_seconds > 0)
	{
		deactivate_nonblock(fd);
	}
	return ret;
}


int read_timeout(int fd, unsigned int wait_seconds)
{
	int ret = 0;
	if (wait_seconds > 0)
	{
		fd_set read_fdset;
		struct timeval timeout;

		FD_ZERO(&read_fdset);
		FD_SET(fd, &read_fdset);

		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		
		
		do
		{
			ret = select(fd + 1, &read_fdset, NULL, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);

		if (ret == 0)
		{
			ret = -1;
			errno = ETIMEDOUT;
		}
		else if (ret == 1)
			ret = 0;
	}

	return ret;
}


int write_timeout(int fd, unsigned int wait_seconds)
{
	int ret = 0;
	if (wait_seconds > 0)
	{
		fd_set write_fdset;
		struct timeval timeout;

		FD_ZERO(&write_fdset);
		FD_SET(fd, &write_fdset);

		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		do
		{
			ret = select(fd + 1, NULL, &write_fdset, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);

		if (ret == 0)
		{
			ret = -1;
			errno = ETIMEDOUT;
		}
		else if (ret == 1)
			ret = 0;
	}

	return ret;
}


int accept_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds)
{
	int ret;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	if (wait_seconds > 0){
		fd_set accept_fdset;
		struct timeval timeout;
		FD_ZERO(&accept_fdset);
		FD_SET(fd, &accept_fdset);
		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		do{
			ret = select(fd + 1, &accept_fdset, NULL, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);
		if (ret == -1)
			return -1;
		else if (ret == 0){
			errno = ETIMEDOUT;
			return -1;
		}
	}


	if (addr != NULL)
		ret = accept(fd, (struct sockaddr*)addr, &addrlen); 
	else
		ret = accept(fd, NULL, NULL);
	if (ret == -1)
		ERR_EXIT("accept");

	return ret;
}


void activate_nonblock(int fd)
{
	int ret;
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		ERR_EXIT("fcntl");

	flags |= O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);
	if (ret == -1)
		ERR_EXIT("fcntl");
}


void deactivate_nonblock(int fd)
{
	int ret;
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		ERR_EXIT("fcntl");

	flags &= ~O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);
	if (ret == -1)
		ERR_EXIT("fcntl");
}



void send_fd(int sock_fd,int send_fd)
{
	int ret;
	struct msghdr msg;
	struct cmsghdr *p_cmsg;
	struct iovec vec;
	char cmsgbuf[CMSG_SPACE(sizeof(send_fd))];
	int *p_fds;
	char sendchar  = 0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	p_cmsg = CMSG_FIRSTHDR(&msg);
	p_cmsg->cmsg_level = SOL_SOCKET;
	p_cmsg->cmsg_type = SCM_RIGHTS;
	p_cmsg->cmsg_len = CMSG_LEN(sizeof(send_fd));
	p_fds = (int * )CMSG_DATA(p_cmsg);
	*p_fds = send_fd;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	vec.iov_base = &sendchar;
	vec.iov_len = sizeof(sendchar);
	ret = sendmsg(sock_fd,&msg,0);
	if(ret != 1)
		ERR_EXIT("sendmsg");

}
int recv_fd (const int sock_fd)
{
        int ret ;
        struct msghdr msg;
        char recvchar;
        struct iovec vec;
        int  recv_fd;
        char cmsgbuf[CMSG_SPACE(sizeof(recv_fd))];
        struct cmsghdr * p_cmsg;
        int *p_fd;
        vec.iov_base = &recvchar;
        vec.iov_len = sizeof(recvchar);
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &vec;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);
        msg.msg_flags = 0;

        p_fd = (int *)CMSG_DATA(CMSG_FIRSTHDR(&msg));
        *p_fd = -1;
        ret = recvmsg(sock_fd,&msg,0);
        if (ret !=1 )
            ERR_EXIT("recvmsg");

        p_cmsg = CMSG_FIRSTHDR(&msg);
        if(p_cmsg == NULL)
            ERR_EXIT("no passed fd");

        p_fd = (int * )CMSG_DATA(p_cmsg);
        recv_fd = *p_fd;
        if(recv_fd == -1)
            ERR_EXIT("no passed fd");

        return recv_fd;


}

const char * statbuf_get_perms(struct stat *sbuf){
	static char perms[] = "----------";
	mode_t mode = sbuf->st_mode;
	switch (mode & S_IFMT){
	case S_IFREG:
		perms[0] = '-';break;
	case S_IFDIR:
		perms[0] = 'd';break;
	case S_IFLNK:
		perms[0] = 'l';break;
	case S_IFIFO:
		perms[0] = 'p';break;
	case S_IFSOCK:
		perms[0] = 's';break;
	case S_IFCHR:
		perms[0] = 'c';break;
	case S_IFBLK:
		perms[0] = 'b';break;
	default:
		perms[0] = '?';
	}

	if(mode & S_IRUSR) perms[1] = 'r';
	if(mode & S_IWUSR) perms[2] = 'w';
	if(mode & S_IXUSR) perms[3] = 'x';

	if(mode & S_IRGRP) perms[4] = 'r';
	if(mode & S_IWGRP) perms[5] = 'w';
	if(mode & S_IXGRP) perms[6] = 'x';

	if(mode & S_IROTH) perms[7] = 'r';
	if(mode & S_IWOTH) perms[8] = 'w';
	if(mode & S_IXOTH) perms[9] = 'x';

	if(mode & S_ISUID) perms[3] = (perms[3] == 'x') ? 's' : 'S';
	if(mode & S_ISGID) perms[6] = (perms[5] == 'x') ? 's' : 'S';
	if(mode & S_ISVTX) perms[9] = (perms[9] == 'x') ? 't' : 'T';
	return perms;
}

const char *statbuf_get_date(struct stat *sbuf){
	static char databuf[64] = {0};
	
	const char *p_data_format = "%b %e %H:%M";
	struct timeval tv;
	gettimeofday(&tv, NULL);
	time_t local_time = tv.tv_sec;
	if(sbuf->st_mtime > local_time || local_time - sbuf->st_mtime > 60*60*24*182){
		p_data_format = "%b %e %Y";
	}
	
	strftime(databuf, sizeof(databuf), p_data_format, localtime(&local_time));
	return databuf;
}

static int lock_internal(int fd, int lock_type){
	int ret;
	struct flock the_lock;
	memset(&the_lock, 0 ,sizeof the_lock);
	the_lock.l_type = lock_type;
	the_lock.l_whence = SEEK_SET;
	the_lock.l_start = 0;
	the_lock.l_len = 0; //整个文件
	
	do{
		ret = fcntl(fd, F_SETLKW, &the_lock);
	}while(ret < 0 && errno == EINTR);
	return ret;

}

int lock_file_read(int fd){
	return lock_internal(fd,F_RDLCK);
}



int lock_file_write(int fd){
	return lock_internal(fd,F_WRLCK);
}

int unlock_file(int fd){
	int ret;
	struct flock the_lock;
	memset(&the_lock, 0 ,sizeof the_lock);
	the_lock.l_type = F_UNLCK;
	the_lock.l_whence = SEEK_SET;
	the_lock.l_start = 0;
	the_lock.l_len = 0; //整个文件
	
	ret = fcntl(fd, F_SETLK, &the_lock);

	return ret;
}

static struct timeval curr_time;

long get_time_sec(){
	if(gettimeofday(&curr_time, NULL) < 0){
		ERR_EXIT("gettimeofday");
	}
	return curr_time.tv_sec;
}
long get_time_usec(){
	return curr_time.tv_usec;
}

void nano_sleep(double sec){
	time_t secs = (int)sec;
	double frac = sec - secs;
	struct timespec ts;
	ts.tv_sec = secs;
	ts.tv_nsec = (long)(frac * 1000000000);
	int ret;
	do{
		ret = nanosleep(&ts,&ts);
	}while(ret == -1 && errno == EINTR);
}

void activate_obbinline(int fd){
	int obb_inline = 1;
	int ret;
	ret = setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &obb_inline, sizeof obb_inline);
	if (ret == -1)
	{
		ERR_EXIT("setsockopt");
	}
			
}

void activate_sigurg(int fd){
	int ret;
	ret = fcntl(fd, F_SETOWN, getpid());
	if(ret == -1){
		ERR_EXIT("setsockopt");
	}

}