#include "str.h"
#include "common.h"

void str_trim_crlf(char *str){
	char *p = &str[strlen(str) - 1];
	while(*p == '\r' || *p == '\n') *p-- = '\0';
}


void str_split(const char *str, char *left, char *right, char c){
	char *p = strchr(str, c);
	if(p == NULL) strcpy(left, str);
	else{
		strncpy(left, str, p-str);
		strcpy(right, p+1);
	}
}


int str_all_space(const char *str){
	while(*str){
		if(!isspace(*str++)) return 0;
	}
	return 1;
}


void str_upper(char *str){
	while(*str){
		*str = toupper(*str);
		str++;
	}
}

long long str_to_ll(const char *str){
	long long ret = 0, idx = 1;
	int len = strlen(str), i;
	for(i = len - 1; i >= 0; i--){
		if(str[i] < '0' || str[i] > '9') return 0;
		ret += (str[i] - '0') * idx;
		idx *= 10;
	}
	return ret;
}

unsigned int str_octal_to_uint(const char *str){
	unsigned int ret = 0, idx = 1;
	int len = strlen(str), i;
	for(i = len - 1; i >= 0; i--){
		if(str[i] < '0' || str[i] > '7') return 0;
		ret += (str[i] - '0') * idx;
		idx *= 8;
	}
	return ret;

	return 0;
}










