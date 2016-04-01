/* Qinsc's ftpserver */ 

/* This is a simple ftpserver. 
 * Created September 2015 by Shuchang Qin 
 * From : Wuhan University of Science and Technology ,Network Engineering
 * E-mail: skyqinsc@gmail.com
 * Repo URL: https://github.com/skyqinsc/MiniFtp
 */ 




#include "common.h"
#include "sysutil.h"
#include "session.h"
#include "str.h"
#include "tunable.h"
#include "parseconf.h"
#include "ftpproto.h"
int main(){
	printf("======MiniFtp log Copyright ©  Qinsc.======\n");
	if(getuid() !=0){
		fprintf(stderr,"miniftpd:must be started as root\n");
		exit(EXIT_FAILURE);
	}
	parseconf_load_file(MINIFTPD_CONF);
	printf("tunable_pasv_enable=%d\n", tunable_pasv_enable);
	printf("tunable_port_enable=%d\n", tunable_port_enable);
	printf("tunable_listen_port=%u\n", tunable_listen_port);
	printf("tunable_max_clients=%u\n", tunable_max_clients);
	printf("tunable_max_per_ip=%u\n", tunable_max_per_ip);
	printf("tunable_accept_timeout=%u\n", tunable_accept_timeout);
	printf("tunable_connect_timeout=%u\n", tunable_connect_timeout);
	printf("tunable_idle_session_timeout=%u\n", tunable_idle_session_timeout);
	printf("tunable_data_connection_timeout=%u\n", tunable_data_connection_timeout);
	printf("tunable_local_umask=0%o\n", tunable_local_umask);
	printf("tunable_upload_max_rate=%u\n", tunable_upload_max_rate);
	printf("tunable_download_max_rate=%u\n", tunable_download_max_rate);
	if(tunable_listen_address) printf("tunable_listen_address=%s\n",tunable_listen_address);
	
	session_t sess ={
		/*控制连接*/
		0,-1, "","","",
		//数据连接
		-1, NULL,- 1,
		/*父子进程通道*/
		-1, -1,
		//FTP协议状态
		0
	};
	signal(SIGCHLD, SIG_IGN);
	int listenfd = tcp_server(tunable_listen_address, 5188);
	int conn;
	pid_t pid;

	while(1){
		conn = accept_timeout(listenfd, NULL,0);
		if(conn == -1){
			ERR_EXIT("accept_timeout");
		}

		pid = fork();
		if(pid == -1) ERR_EXIT("fork");

		if(pid == 0){
			close(listenfd);
			sess.ctrl_fd = conn;
			begin_session(&sess);
		}
		else close(conn);
	}
	return 0;
}
