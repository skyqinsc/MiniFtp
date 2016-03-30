#include "common.h"
#include "sysutil.h"
#include "session.h"
int main(){
	
	if(getuid() !=0){
		fprintf(stderr,"miniftpd:must be started as root\n");
		exit(EXIT_FAILURE);
	}


	session_t sess ={
		/*控制连接*/
		-1, "","","",
		/*父子进程通道*/
		-1, -1
	};
	int listenfd = tcp_server(NULL, 5188);
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
