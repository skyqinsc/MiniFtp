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

int list_common(session_t *sess);

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




void handle_child(session_t *sess){
	ftp_reply(sess, FTP_GREET, "(miniftpd 1.0 @Copyright Qinsc)");
	int ret;
	while(1){
		memset(sess->cmdline, 0, sizeof sess->cmdline);
		memset(sess->cmd, 0, sizeof sess->cmd);
		memset(sess->arg, 0, sizeof sess->arg);

		ret = readline(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);
		if(ret == -1)
			ERR_EXIT("readline");
		else if(ret == 0)
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


int list_common(session_t *sess){
	DIR *dir = opendir(".");
	if(dir == NULL) return 0;
	struct dirent *dt;
	struct stat sbuf;
	while((dt = readdir(dir)) != NULL){
		if(lstat(dt->d_name, &sbuf) < 0 || dt->d_name[0] == '.') continue;
		char perms[] = "----------";
		mode_t mode = sbuf.st_mode;
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

		char buf[1024] = {0};
		int off = 0;
		off += sprintf(buf + off, "%s ",perms);
		off += sprintf(buf + off, "%3d %-8d %-8d ", (int)sbuf.st_nlink, (int)sbuf.st_uid, (int)sbuf.st_gid);
		off += sprintf(buf + off, "%8lu ", (unsigned long)sbuf.st_size);
		const char *p_data_format = "%b %e %H:%M";
		struct timeval tv;
		gettimeofday(&tv, NULL);
		time_t local_time = tv.tv_sec;
		if(sbuf.st_mtime > local_time || local_time - sbuf.st_mtime > 60*60*24*182){
			p_data_format = "%b %e %Y";
		}
		char databuf[64] = {0};
		strftime(databuf, sizeof(databuf), p_data_format, localtime(&local_time));
		off += sprintf(buf + off, "%s ", databuf);
		if(S_ISLNK(sbuf.st_mode)){
			char tmp[1024] = {0};
			readlink(dt->d_name, tmp, sizeof(tmp));
			off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name, tmp);
		}
		else
			off += sprintf(buf + off, "%s\r\n", dt->d_name);
		//printf("%s", buf);
		writen(sess->data_fd, buf, strlen(buf));
	}
	closedir(dir);
	return 1;
}

int port_active(session_t *sess){
	if(sess->port_addr){
		if(pasv_active(sess)){
			fprintf(stderr, "Both PASV And PORT Are Active!");
			return 0;
		}
		return 1;
	}
	return 0;
}

int pasv_active(session_t *sess){
	if(sess->pasv_listen_fd != -1){
		if(port_active(sess)){
			fprintf(stderr, "Both PASV And PORT Are Active!");
			return 0;
		}
		return 1;
	}
	return 0;
}

int get_stransfer_fd(session_t *sess){
	//检测是否收到port或pasv
	if(!port_active(sess) && !pasv_active(sess)){
		ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first.");
		return 0;
	}
	if(port_active(sess)){
		//socket -> bind 20
		//tcp_client(20);
		int fd = tcp_client(0);
		//connect
		if(connect_timeout(fd, sess->port_addr, tunable_connect_timeout) < 0){
			close(fd);
			return 0;
		}
		printf("=====Transfer Success====\n");
		sess->data_fd = fd;
		if(sess->port_addr){
			free(sess->port_addr);
			sess->port_addr = NULL;
		}
	}
	if(pasv_active(sess)){
		int conn = accept_timeout(sess->pasv_listen_fd, NULL, tunable_accept_timeout);
		close(sess->pasv_listen_fd);
		if(conn < 0) return 0;
		close(sess->pasv_listen_fd);
		sess->data_fd = conn;
	}
	return 1;
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


void do_cwd(session_t *sess){}
void do_cdup(session_t *sess){}
void do_quit(session_t *sess){}
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
	 int fd = tcp_server(ip, 0);
	 struct sockaddr_in addr;
	 socklen_t addrlen = sizeof(struct sockaddr);
	 if(getsockname(fd, (struct sockaddr*)&addr, &addrlen) < 0)
		 ERR_EXIT("getsockname");
	 unsigned short port = ntohs(addr.sin_port);

	 unsigned int v[6];
	 sscanf(ip,"%u.%u.%u.%u",v, v+1, v+2, v+3);
	 char text[1024] = {0};
	 sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).",
		 v[0], v[1], v[2], v[3], port>>8, port&0x00FF);
	 ftp_reply(sess, FTP_PASVOK, text);
	 sess->pasv_listen_fd = fd;
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
void do_retr(session_t *sess){}
void do_stor(session_t *sess){}
void do_appe(session_t *sess){}
void do_list(session_t *sess){
	//创建数据连接
	if(get_stransfer_fd(sess) == 0) return;
	//150
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");
	//传输列表
	list_common(sess);
	//关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	//226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}
void do_nlst(session_t *sess){}
void do_rest(session_t *sess){}
void do_abor(session_t *sess){}
void do_pwd(session_t *sess){
	char dir[1024] = {0};
	char text[1024] = {0};
	getcwd(dir, 1024);
	sprintf(text, "\"%s\"", dir);
	ftp_reply(sess, FTP_PWDOK, text);
}
void do_mkd(session_t *sess){}
void do_rmd(session_t *sess){}
void do_dele(session_t *sess){}
void do_rnfr(session_t *sess){}
void do_rnto(session_t *sess){}
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
void do_size(session_t *sess){}
void do_stat(session_t *sess){}
void do_noop(session_t *sess){}
void do_help(session_t *sess){}
