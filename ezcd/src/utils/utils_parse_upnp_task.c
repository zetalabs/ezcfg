/* ============================================================================
 * Project Name : ezbox Configuration Daemon
 * Module Name  : utils_parse_upnp_task.c
 *
 * Description  : parse UPnP task line to argv[] 
 *
 * Copyright (C) 2008-2013 by ezbox-project
 *
 * History      Rev       Description
 * 2011-12-22   0.1       Write it from scratch
 * ============================================================================
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/un.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <syslog.h>
#include <ctype.h>
#include <stdarg.h>
#include <dlfcn.h>

#include "ezcd.h"

/*********************************
 * upnp task format:
 *   action:command:execute time:repeat_interval
 *
 * action: add|del
 * command: string for utils_system()
 * execute_time: sysinfo.uptime, if 0 execute at exit
 * repeat_interval: repeat interval in seconds, if 0 not repeat
 *********************************/
/* return parsed args number */
int utils_parse_upnp_task(char *buf, size_t size, char **argv)
{
	char *p;
	//int i;
	int argc;

	argc = 0;
	//i = 0;
	p = buf;
	while((argc < RC_MAX_ARGS - 1) && (*p != '\0')) {
		/* skip blank char */
		while(IS_BLANK(*p)) {
			*p = '\0';
			p++;
		}
		if (*p == '\0')
			break;

		/* find argv[] start */
		argv[argc] = p;
		argc++;
		p++;
		while(!IS_COLON(*p) && (*p != '\0')) p++;

		/* 0-terminated argv */
		if (IS_COLON(*p)) { *p = '\0'; p++; }
	}

	/* check if all string has been parsed */
	if (*p != '\0') {
		return -1;
	}

	/* final argv[] must be NULL */
	argv[argc] = NULL;
	return (argc);
}
