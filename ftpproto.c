#include "ftpproto.h"
#include "sysutil.h"

void handle_child(session_t *sess){
	writen(sess->ctrl_fd,"220 (miniftpd 1.0 @Copyright Qinsc)\r\n", strlen("220 (miniftpd 1.0 @Copyright Qinsc)\r\n"));
	while(1){
		memset(sess->cmdline, 0, sizeof sess->cmdline);
		memset(sess->cmd, 0, sizeof sess->cmd);
		memset(sess->arg, 0, sizeof sess->arg);

		readline(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);
		//解析FTP命令和参数
		
		//处理FTP命令

	}
}
