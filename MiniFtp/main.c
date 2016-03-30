#include "common.h"
#include "sysutil.h"
#include "session.h"
#include "str.h"
#include "tunable.h"
#include "parseconf.h"

int main(){
	char *str="000711";
	printf("%u\n", str_octal_to_uint(str));
	if(getuid() !=0){
		fprintf(stderr,"miniftpd:must be started as root\n");
		exit(EXIT_FAILURE);
	}

	parseconf_load_file(MINIFTPD_CONF);
	printf("%d %d %u %u %u %u %u %u %u 0%o %u %u:\n",
		tunable_pasv_enable,
		tunable_port_enable,
		tunable_listen_port,
		tunable_max_clients,
		tunable_max_per_ip,
		tunable_accept_timeout,
		tunable_connect_timeout,
		tunable_idle_session_timeout,
		tunable_data_connection_timeout,
		tunable_local_umask,
		tunable_upload_max_rate,
		tunable_download_max_rate
	);
	if(tunable_listen_address) printf(" : %s\n",tunable_listen_address);
	session_t sess ={
		/*控制连接*/
		0,-1, "","","",
		/*父子进程通道*/
		-1, -1,
		//FTP协议状态
		0
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
