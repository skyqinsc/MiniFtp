#include "ftpproto.h"
#include "sysutil.h"
#include "str.h"
#include "ftpcodes.h"
#include "tunable.h"

static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
static void do_port(session_t *sess);
static void do_pasv(session_t *sess);
static void do_type(session_t *sess);
static void do_stru(session_t *sess);
static void do_mode(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_appe(session_t *sess);
static void do_list(session_t *sess);
static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
static void do_abor(session_t *sess);
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_site(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_size(session_t *sess);
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);
static void do_help(session_t *sess);


void ftp_reply(session_t *sess,int status, const char *text);
void ftp_lreply(session_t *sess,int status, const char *text);
int port_active(session_t *sess);
int pasv_active(session_t *sess);
int get_stransfer_fd(session_t *sess);

void handle_sigurg(int sig);
void handle_alarm_ctrl(int sig);
void handle_alarm_data(int sig);
void start_cmdio_alarm();
void start_data_alarm();

void check_abor(session_t *sess);

int list_common(session_t *sess, int detail);
void upload_common(session_t *sess, int is_append);

void limit_rate(session_t *sess,int bytes_transfered, int is_upload);

typedef struct ftpcmd
{
	const char *cmd;
	void (*cmd_handler)(session_t *sess);
}ftpcmd_t;
static ftpcmd_t ctrl_cmds[]=
{
	/*访问控制命令*/
	{"USER",	do_user},
	{"PASS",	do_pass},
	{"CWD",		do_cwd},
	{"XCWD",	do_cwd},
	{"CDUP",	do_cdup},
	{"XCUP",	do_cdup},
	{"QUIT",	do_quit},
	{"ACCT",	NULL},
	{"SMNT",	NULL},
	{"REIN",	NULL},
	/*传输参数命令*/
	{"PORT",	do_port},
	{"PASV",	do_pasv},
	{"TYPE",	do_type},
	{"STRU",	do_stru},
	{"MODE",	do_mode},
	/* 服务命令 */
	{"RETR",	do_retr},
	{"STOR",	do_stor},
	{"APPE",	do_appe},
	{"LIST",	do_list},
	{"NLST",	do_nlst},
	{"REST",	do_rest},
	{"ABOR",	do_abor},
	{"\377\364\377\362ABOR",do_abor},
	{"PWD",		do_pwd},
	{"XPWD",	do_pwd},
	{"MKD",		do_mkd},
	{"XMKD",	do_mkd},
	{"RMD",		do_rmd},
	{"XRMD",	do_rmd},
	{"DELE",	do_dele},
	{"RNFR",	do_rnfr},
	{"RNTO",	do_rnto},
	{"SITE",	do_site},
	{"SYST",	do_syst},
	{"FEAT",	do_feat},
	{"SIZE",	do_size},
	{"STAT",	do_stat},
	{"NOOP",	do_noop},
	{"HELP",	do_help},
	{"STOU",	NULL},
	{"ALLO",	NULL}
};

session_t *p_sess;

void handle_sigurg(int sig){
	if(p_sess->data_fd == -1){
		return;
	}
	char cmdline[MAX_COMMAND_LINE] = {0};
	int ret = readline(p_sess->ctrl_fd, cmdline, MAX_COMMAND_LINE);
	if(ret <= 0){
		ERR_EXIT("readline");
	}
	str_trim_crlf(cmdline);
	if (strcmp(cmdline, "ABOR") == 0 
		&& strcmp(cmdline, "\377\364\377\362ABOR") == 0)
	{
		p_sess->abor_received = 1;
		shutdown(p_sess->data_fd,SHUT_RDWR);
	}
	else{
		ftp_reply(p_sess, FTP_BADCMD, "Unknow command.");
	}
}

void handle_alarm_ctrl(int sig){
	shutdown(p_sess->ctrl_fd, SHUT_RD);
	ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Timeout.");
	shutdown(p_sess->ctrl_fd, SHUT_WR);
	exit(EXIT_FAILURE);
}
void handle_alarm_data(int sig){
	if(p_sess->data_process == 0){
		ftp_reply(p_sess, FTP_DATA_TIMEOUT, "Data Timeout.Reconnect！");
		exit(EXIT_FAILURE);
	}
	//当前有数据连接，但收到超时
	p_sess->data_process = 0;
	start_data_alarm();
}

void check_abor(session_t *sess){
	if(sess->abor_received){
		sess->abor_received = 0;
		ftp_reply(sess, FTP_ABOROK, "ABOR success.");
	}
}


void start_cmdio_alarm(){
	if(tunable_idle_session_timeout > 0){
		signal(SIGALRM, handle_alarm_ctrl);//安装信号
		alarm(tunable_idle_session_timeout);//启动闹钟
	}
}

void start_data_alarm(){
	if(tunable_data_connection_timeout > 0){
		signal(SIGALRM, handle_alarm_data);//安装信号
		alarm(tunable_data_connection_timeout);//启动闹钟
	}
	else{
		if(tunable_idle_session_timeout > 0)
			alarm(0);//关闭先去安装的闹钟
	}
}


void handle_child(session_t *sess){
	ftp_reply(sess, FTP_GREET, "(miniftpd 1.0 @Copyright Qinsc)");
	int ret;
	while(1){
		memset(sess->cmdline, 0, sizeof sess->cmdline);
		memset(sess->cmd, 0, sizeof sess->cmd);
		memset(sess->arg, 0, sizeof sess->arg);

		start_cmdio_alarm();
		ret = readline(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);
		if(ret == -1)
			ERR_EXIT("readline");
		else if(ret == 0) //客户端断开连接，服务进程退出
			exit(EXIT_SUCCESS);
		//去除\r\n
		str_trim_crlf(sess->cmdline);
		printf("cmdline=[%s]\n", sess->cmdline);
		//解析FTP命令和参数
		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
		printf("cmd=[%s] arg=[%s]\n", sess->cmd, sess->arg);
		//命令处理成大写
		str_upper(sess->cmd);
		//处理FTP命令
		int size = sizeof(ctrl_cmds) / sizeof(ctrl_cmds[0]);
		int i;
		for(i = 0; i < size; i++){
			if(strcmp(sess->cmd, ctrl_cmds[i].cmd) == 0){
				if(ctrl_cmds[i].cmd_handler){
					ctrl_cmds[i].cmd_handler(sess);
				}
				else{
					ftp_reply(sess, FTP_COMMANDNOTIMPL, "Unimplement command.");
				}
				break;
			}
		}
		if(i == size){
			ftp_reply(sess, FTP_BADCMD, "Unknown command.");
		}
	}
}

void ftp_reply(session_t *sess,int status, const char *text){
	char buf[1024] = {0};
	sprintf(buf, "%d %s\r\n", status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));
}

void ftp_lreply(session_t *sess,int status, const char *text){
	char buf[1024] = {0};
	sprintf(buf, "%d-%s\r\n", status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));
}


int list_common(session_t *sess, int detail){
	DIR *dir = opendir(".");
	if(dir == NULL) return 0;
	struct dirent *dt;
	struct stat sbuf;
	while((dt = readdir(dir)) != NULL){
		if(lstat(dt->d_name, &sbuf) < 0 || dt->d_name[0] == '.') continue;
		char buf[1024] = {0};
		if(detail){
			const char *perms = statbuf_get_perms(&sbuf);

			int off = 0;
			off += sprintf(buf + off, "%s ",perms);
			off += sprintf(buf + off, "%3d %-8d %-8d ", (int)sbuf.st_nlink, (int)sbuf.st_uid, (int)sbuf.st_gid);
			off += sprintf(buf + off, "%8lu ", (unsigned long)sbuf.st_size);

			const char *databuf = statbuf_get_date(&sbuf);
			
			off += sprintf(buf + off, "%s ", databuf);
			if(S_ISLNK(sbuf.st_mode)){
				char tmp[1024] = {0};
				readlink(dt->d_name, tmp, sizeof(tmp));
				off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name, tmp);
			}
			else
				off += sprintf(buf + off, "%s\r\n", dt->d_name);
		}
		else{
			sprintf(buf, "%s\r\n", dt->d_name);
		}

		printf("%s", buf);
		writen(sess->data_fd, buf, strlen(buf));
	}
	closedir(dir);
	return 1;
}

void limit_rate(session_t *sess,int bytes_transfered, int is_upload){
	sess->data_process = 1; //设置属于数据传输！

	long curr_sec = get_time_sec();
	long curr_usec = get_time_usec();

	double elapsed;
	elapsed = curr_sec - sess->bw_transfer_start_sec;
	elapsed += (curr_usec - sess->bw_transfer_start_usec) / 1000000.;

	if(elapsed <= 0) elapsed = 0.01;
	double bw_rate = bytes_transfered / elapsed;
	double rate_ratio;
	if(is_upload){
		if(bw_rate <= sess->bw_upload_max_rate){
			sess->bw_transfer_start_sec = curr_sec;
			sess->bw_transfer_start_usec = curr_usec;
			return;
		}
		rate_ratio = bw_rate / sess->bw_upload_max_rate;
	}
	else{
		if(bw_rate <= sess->bw_download_max_rate){
			sess->bw_transfer_start_sec = curr_sec;
			sess->bw_transfer_start_usec = curr_usec;
			return;
		}
		rate_ratio = bw_rate / sess->bw_download_max_rate;
	}
	double pause_time = (rate_ratio - 1.0)*elapsed;
	nano_sleep(pause_time);
	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();
}

void upload_common(session_t *sess, int is_append){
	//文件下载
	//断点续传
	//创建数据连接
	if(get_stransfer_fd(sess) == 0) return;
	
	long long offset = sess->restart_pos;
	
	sess->restart_pos = 0;
	
	//打开文件
	int fd = open(sess->arg, O_CREAT | O_WRONLY, 0666);
	if(fd == -1){
		ftp_reply(sess, FTP_UPLOADFAIL, "Failed to create file.");
		return;
	}
	int ret;
	//加写锁
	ret = lock_file_write(fd);
	if(ret == -1){
		
	}
	if(!is_append){
		if(offset == 0){
			ftruncate(fd, 0);
			if(lseek(fd, 0, SEEK_SET) < 0){
				ftp_reply(sess, FTP_UPLOADFAIL, "Failed to create file.");
				return;
			}
		}
		else{
			if(lseek(fd,offset, SEEK_SET) < 0){
				ftp_reply(sess, FTP_UPLOADFAIL, "Failed to create file.");
				return;
			}
		}
	}
	else{    // append模式
		if(lseek(fd, 0,SEEK_END) < 0){
			ftp_reply(sess, FTP_UPLOADFAIL, "Failed to create file.");
			return;
		}
	}
	struct stat sbuf;
	ret = fstat(fd, &sbuf);
	//150 Opening BINARY mode data connection for /home/qinsc/Documents/github.algocode.cn/404.md (324 bytes).
	char text[1024] = {0};
	if(sess->is_ascii){
		sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes).",
			sess->arg, (long long)sbuf.st_size);
	}
	else{
		sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes).",
			sess->arg, (long long)sbuf.st_size);
	}
	ftp_reply(sess, FTP_DATACONN, text);

	//上传文件
	

	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();

	int flag = 0;
	int buf[1024] = {0};
	while(1){
		ret = read(sess->data_fd, buf, sizeof(buf));
		if(ret == -1){
			if(errno == EINTR) continue;
			else{
				flag = 1;	
				break;
			}
		}
		else if(ret == 0){
			flag = 0;
			break;
		}

		limit_rate(sess, ret, 1);
		if(sess->abor_received){
			flag = 2;
			break;
		}
		if(writen(fd, buf, ret) !=ret){
			flag = 2;
			break;
		}
	}

	//关闭数据套接字
	close(fd);
	close(sess->data_fd);
	sess->data_fd = -1;
	if(flag == 0 && !sess->abor_received){
		//226
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete");
	}
	else if(flag == 1){
		//451
		ftp_reply(sess, FTP_BADSENDFILE, "Fail to write local file");
	}
	else{
		//426
		ftp_reply(sess, FTP_BADSENDNET, "Fail to read network steam");
	}
	check_abor(sess);
	start_cmdio_alarm();
}


int port_active(session_t *sess){
	if(sess->port_addr){
		if(pasv_active(sess)){
			fprintf(stderr, "Both PASV And PORT Are Active!");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	return 0;
}

int pasv_active(session_t *sess){
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
	int active = priv_sock_get_int(sess->child_fd);
	
	if(active){
		if(port_active(sess)){
			fprintf(stderr, "Both PASV And PORT Are Active!");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	
	return 0;
}

int get_port_fd(session_t *sess){
	priv_sock_send_cmd(sess->child_fd,  PRIV_SOCK_GET_DATA_SOCK);
	unsigned short port = ntohs(sess->port_addr->sin_port);
	char *ip = inet_ntoa(sess->port_addr->sin_addr);
	priv_sock_send_int(sess->child_fd,(int)port);
	priv_sock_send_buf(sess->child_fd, ip, strlen(ip));

	char res = priv_sock_get_result(sess->child_fd);

	if(res == PRIV_SOCK_RESULT_BAD) return 0;
	else if(res == PRIV_SOCK_RESULT_OK){
		sess->data_fd = recv_fd(sess->child_fd);
	}
	return 1;
}

int get_pasv_fd(session_t *sess){
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
	int res = priv_sock_get_result(sess->child_fd);
	if(res == PRIV_SOCK_RESULT_BAD) return 0;
	else if( res == PRIV_SOCK_RESULT_OK){
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}
	return 1;
}

int get_stransfer_fd(session_t *sess){
	//检测是否收到port或pasv
	
	if(!port_active(sess) && !pasv_active(sess)){
		ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first.");
		return 0;
	}
	int ret = 1;
	if(port_active(sess)){
		
		if(get_port_fd(sess) == 0) ret = 0;
		if(sess->port_addr){
			free(sess->port_addr);
			sess->port_addr = NULL;
		}
	}
	if(pasv_active(sess)){

		if(get_pasv_fd(sess) == 0) ret = 0;

	}
	if(ret){
		//重新安装闹钟！
		start_data_alarm();
	}
	return ret;
}

void do_user(session_t *sess){
	//USER qinsc
	struct passwd *pw = getpwnam(sess->arg);
	if(pw == NULL){
		ftp_reply(sess, FTP_LOGINERR, "Login incorrecti.");
		return;
	}
	sess->uid = pw->pw_uid;
	ftp_reply(sess, FTP_GIVEPWORD, "Please spacify the password.");
}

void do_pass(session_t *sess){
	//PASS 111222
	struct passwd *pw = getpwuid(sess->uid);
	if(pw == NULL){// password用户不存在
		ftp_reply(sess, FTP_LOGINERR, "Login incorrecti.");
		return;
	}
	sess->uid = pw->pw_uid;
	struct spwd *sp = getspnam(pw->pw_name);
	if(sp == NULL){// shadow不存在
		ftp_reply(sess, FTP_LOGINERR, "Login incorrecti.");
		return;
	}

	signal(SIGURG, handle_sigurg);
	activate_sigurg(sess->ctrl_fd);


	umask(tunable_local_umask);
	setegid(pw->pw_gid);
	seteuid(pw->pw_uid);
	chdir(pw->pw_dir);
	//将明文加密
	char *decodepwd = crypt(sess->arg, sp->sp_pwdp);
	if(strcmp(decodepwd, sp->sp_pwdp) == 0)
		ftp_reply(sess, FTP_LOGINOK, "Login successful.");
	else
		ftp_reply(sess, FTP_LOGINERR, "Login incorrecti.");
}


void do_cwd(session_t *sess){
	if(chdir(sess->arg) < 0){
		ftp_reply(sess, FTP_FILEFAIL, "Failed to change directory.");
		return;
	}
	ftp_reply(sess, FTP_CWDOK,"Directory successfully changed.");

}
void do_cdup(session_t *sess){
	if(chdir("..") < 0){
		ftp_reply(sess, FTP_FILEFAIL, "Failed to change directory.");
		return;
	}
	ftp_reply(sess, FTP_CWDOK,"Directory successfully changed.");
}
void do_quit(session_t *sess){
	ftp_reply(sess, FTP_GOODBYE,"GoodBye!");
	exit(EXIT_SUCCESS);
}
void do_port(session_t *sess){
	//PORT 192,168,142,1,221,142
	unsigned int v[6];
	sscanf(sess->arg,"%u,%u,%u,%u,%u,%u",&v[2],&v[3],&v[4],&v[5],&v[0],&v[1]);
	sess->port_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	memset(sess->port_addr, 0, sizeof(struct sockaddr_in));
	sess->port_addr->sin_family=AF_INET;
	unsigned char *p = (unsigned char *)&sess->port_addr->sin_port;
	p[0] = v[0];
	p[1] = v[1];

	p = (unsigned char*)&sess->port_addr->sin_addr;
	p[0] = v[2];
	p[1] = v[3];
	p[2] = v[4];
	p[3] = v[5];

	ftp_reply(sess, FTP_PORTOK,"PORT command successful.Consider using PASV.");
}

void do_pasv(session_t *sess){
	 //227 Entering Passive Mode (192,168,142,130,215,180).
	 char ip[16] = {0};
	 getlocalip(ip);

	 priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
	 unsigned short port = (unsigned short)priv_sock_get_int(sess->child_fd);
	 unsigned int v[4];
	 sscanf(ip,"%u.%u.%u.%u",v, v+1, v+2, v+3);
	 char text[1024] = {0};
	 sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).",
		 v[0], v[1], v[2], v[3], port>>8, port&0x00FF);
	 ftp_reply(sess, FTP_PASVOK, text);
}


void do_type(session_t *sess){
	 if(strcmp(sess->arg, "A") == 0){
		 sess->is_ascii = 1;
		 ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
	 }
	 else if(strcmp(sess->arg, "I") == 0){
		 sess->is_ascii = 0;
		 ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
	 }
	 else{
		 ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command");
	 }
}
void do_stru(session_t *sess){}
void do_mode(session_t *sess){}
void do_retr(session_t *sess){
	//文件下载
	//断点续传
	//创建数据连接
	if(get_stransfer_fd(sess) == 0) return;
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	
	//打开文件
	int fd = open(sess->arg, O_RDONLY);
	if(fd == -1){
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}
	int ret;
	//加读锁
	ret = lock_file_read(fd);
	if(ret == -1){
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}
	//文件是否是普通文件
	struct stat sbuf;
	ret = fstat(fd, &sbuf);
	if(!S_ISREG(sbuf.st_mode)){
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	if(offset != 0){
		ret = lseek(fd,offset, SEEK_SET);
		if(ret == -1){
			ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
			return;
		}
	}
	//150 Opening BINARY mode data connection for /home/qinsc/Documents/github.algocode.cn/404.md (324 bytes).
	char text[1024] = {0};
	if(sess->is_ascii){
		sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes).",
			sess->arg, (long long)sbuf.st_size);
	}
	else{
		sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes).",
			sess->arg, (long long)sbuf.st_size);
	}
	ftp_reply(sess, FTP_DATACONN, text);

	//传输文件
	int flag = 0;

	//sendfile(see->data_fd, fd,)
	long long bytes_to_send = sbuf.st_size;
	bytes_to_send = bytes_to_send > offset?bytes_to_send - offset:0;

	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();
	while(bytes_to_send){
		int rest = bytes_to_send > 4096 ? 4096 : bytes_to_send;
		ret = sendfile(sess->data_fd, fd, NULL, rest);
		if(ret == -1){
			flag = 2;
			break;
		}
		limit_rate(sess, ret, 0);
		if(sess->abor_received){
			flag = 2;
			break;
		}
		bytes_to_send -= ret;
	}
	//关闭数据套接字
	close(fd);
	close(sess->data_fd);
	sess->data_fd = -1;
	if(flag == 0 && !sess->abor_received){
		//226
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete");
	}
	else if(flag == 1){
		//451
		ftp_reply(sess, FTP_BADSENDFILE, "Fail to read local file");
	}
	else{
		//426
		ftp_reply(sess, FTP_BADSENDNET, "Fail to write network steam");
	}
	start_cmdio_alarm();
	check_abor(sess);
}

void do_stor(session_t *sess){
	upload_common(sess, 0);
}

void do_appe(session_t *sess){
	upload_common(sess, 1);
}


void do_list(session_t *sess){
	//创建数据连接
	if(get_stransfer_fd(sess) == 0) return;
	//150
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");
	//传输列表
	list_common(sess,1);
	//关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	//226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}


void do_nlst(session_t *sess){
	//创建数据连接
	if(get_stransfer_fd(sess) == 0) return;
	//150
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");
	//传输列表
	list_common(sess,0);
	//关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	//226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}


void do_rest(session_t *sess){
	//350 Restart position accepted (0)
	sess->restart_pos= str_to_ll(sess->arg);
	char text[1024] = {0};
	sprintf(text, "Restart position accepted (%lld).",sess->restart_pos);
	ftp_reply(sess, FTP_RESTOK, text);
}
void do_abor(session_t *sess){
	ftp_reply(sess, FTP_ABOR_NOCONN, "No transfer to ABOR");
}


void do_pwd(session_t *sess){
	char dir[1024] = {0};
	char text[1024] = {0};
	getcwd(dir, 1024);
	sprintf(text, "\"%s\"", dir);
	ftp_reply(sess, FTP_PWDOK, text);
}


void do_mkd(session_t *sess){
	// 0777 & umask
	if(mkdir(sess->arg, 0777) < 0){
		ftp_reply(sess, FTP_FILEFAIL, "Create directory operation failed.");
		return;
	}
	
	char text[1024] = {0};
	if(sess->arg[0] == '/'){
		sprintf(text, "%s created", sess->arg);
	}
	else{
		char dir[1024] = {0};
		getcwd(dir, 1024);
		if(dir[strlen(dir) - 1] == '/')
			sprintf(text, "%s%s created", dir, sess->arg);
		else
			sprintf(text, "%s/%s created", dir, sess->arg);
	}
	ftp_reply(sess, FTP_MKDIROK, text);
}


void do_rmd(session_t *sess){
	if(rmdir(sess->arg) < 0){
		ftp_reply(sess,FTP_FILEFAIL, "Remove directory operation fail.");
		return;
	}
	ftp_reply(sess,FTP_RMDIROK, "Remove directory operation successful.");
}


void do_dele(session_t *sess){
	if(unlink(sess->arg) < 0){
		ftp_reply(sess,FTP_FILEFAIL, "Delete operation fail.");
		return;
	}
	ftp_reply(sess,FTP_DELEOK, "Delete operation sucessful.");
}


void do_rnfr(session_t *sess){
	//350 Ready for RNTO.
	sess->rnfr_name = (char*)malloc(strlen(sess->arg)+1);
	memset(sess->rnfr_name, 0, strlen(sess->arg)+1);
	strcpy(sess->rnfr_name, sess->arg);
	ftp_reply(sess,FTP_RNFROK, "Ready for RNTO.");
}


void do_rnto(session_t *sess){
	if(sess->rnfr_name == NULL){
		//503 RNFR required first.
		ftp_reply(sess,FTP_NEEDRNFR, "RNFR required first.");
		return;
	}
	rename(sess->rnfr_name, sess->arg);
	ftp_reply(sess,FTP_RENAMEOK, "Rename successful.");
	free(sess->rnfr_name);
	sess->rnfr_name = NULL;
}
void do_site(session_t *sess){}


void do_syst(session_t *sess){
	ftp_reply(sess, FTP_SYSTOK, "UNIX Type: L8");
}

void do_feat(session_t *sess){
	ftp_lreply(sess, FTP_FEAT, "Features:");
	writen(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"));
	writen(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV\r\n"));
	writen(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"));
	writen(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"));
	writen(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"));
	writen(sess->ctrl_fd, " SIZE\r\n", strlen(" SIZE\r\n"));
	writen(sess->ctrl_fd, " TVFS\r\n", strlen(" TVFS\r\n"));
	writen(sess->ctrl_fd, " UTF8\r\n", strlen(" UTF8\r\n"));
	ftp_reply(sess, FTP_FEAT, "End");
}
void do_size(session_t *sess){
	//550 Could not get file size.
	struct stat buf;
	{
	};
	if(stat(sess->arg, &buf) < 0){
		ftp_reply(sess,FTP_FILEFAIL, "SIZE operation fail.");
		return;
	}
	if(!S_ISREG(buf.st_mode)){
		ftp_reply(sess,FTP_FILEFAIL, "Could not get file size.");
		return;
	}
	char text[1024] = {0};
	sprintf(text, "%lld",(long long)buf.st_size);
	ftp_reply(sess,FTP_SIZEOK, text);
}
void do_stat(session_t *sess){
	//ftp_reply(sess,FTP_STATOK, text);
}
void do_noop(session_t *sess){
	ftp_reply(sess, FTP_NOOPOK, "Noop ok!");
}
void do_help(session_t *sess){

}



