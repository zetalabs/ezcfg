/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 * ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : composite/socket_agent/socket_agent_worker_thread_nv_json_http.c
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2016 by ezbox-project
 *
 * History      Rev       Description
 * 2015-12-29   0.1       Modify it from agent/agent_worker_nv_json_http.c
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stddef.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/un.h>
#include <pthread.h>

#include "ezcfg.h"
#include "ezcfg-private.h"

#include "socket_agent_local.h"

#define WEB_PATH "/tmp/ezcfg/agent/http_server/web/admin"
#define DOWNLOAD_PATH "/tmp/ezcfg/agent/http_server/download"

static void send_http_page(struct worker_thread_arg *arg, int status,
                            const char *reason, const char *fmt, ...)
{
  char buf[EZCFG_BUFFER_SIZE];
  va_list ap;
  int len;

  buf[0] = '\0';
  len = 0;
    va_start(ap, fmt);
    len += vsnprintf(buf + len, sizeof(buf) - len, fmt, ap);
    va_end(ap);
    arg->num_bytes_sent = len;
  local_socket_agent_worker_thread_printf(arg,
		              "HTTP/1.1 %d %s\r\n"
		              "Content-Type: text/html\r\n"
		              "Content-Length: %d\r\n"
		              "Connection: close\r\n"
		              "\r\n%s", status, reason, len, buf);
}

static void get_file(char *buf, char *file)
{
	FILE *fp = fopen(file, "r");
	if (fp) {
	int ret = fread(buf, 1, 4096, fp);
	printf("file %s size %d\n", file, ret);
	fclose(fp);
	} else
	printf("fopen(%s) error:%s\n", file, strerror(errno));
}

static void handle_http_request_get(struct worker_thread_arg *arg, struct ezcfg_http *http)
{
  char buf[4096] = {0};
  char page[128] = {0};
  //char *uri = ezcfg_http_get_request_uri(http);
  //snprintf(page, sizeof(page), "%s/login.html", WEB_PATH);
  snprintf(page, sizeof(page), "%s/upload.html", WEB_PATH);
  get_file(buf, page);
  //	if (strcmp(uri, "/") == 0 || strcmp(uri, "/index.html") == 0) {
           send_http_page(arg, 200, "OK", "%s", buf);
  //	}
}

static int handle_http_request_post_upload(struct worker_thread_arg *arg, struct ezcfg_http *http)
{
#if 0
  char *msg_body;
  int msg_body_len;
  char file[128];
  msg_body = ezcfg_http_get_message_body(http);
  msg_body_len = ezcfg_http_get_message_body_len(http);
  if (msg_body != NULL && msg_body_len > 0) {
	char *p;
	if ((p = strstr(msg_body, "="))) {
		*p = '\0';
		p++;
		if (strcmp(msg_body, "firmware") == 0) {
			strcpy(file, p);
			printf("file [%s]\n", file);
		} else
			return -1;
	}
  }
  return -1;
#endif
  return 0;
}



#if 0
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=---------------------------18293431215886960621108763925

-----------------------------16755488591442947828762896200
Content-Disposition: form-data; name="firmware"; filename="delete_all_units.sh"
Content-Type: text/x-sh

cc pr:Default
delallunits

-----------------------------16755488591442947828762896200--
#endif
static void get_val(char *b, char *data, char *key, char end)
{
	char *p, *p2;
	if ((p = strstr(data, key))) {
		p += strlen(key);
		if (end == '\0')
			memcpy(b, p, strlen(p));
		else if ((p2 = strchr(p, end)))
			memcpy(b, p, p2 - p);
	}
}

#if 0
-----------------------------578979121967419241084918832
Content-Disposition: form-data; name="firmware"; filename="batch_shell_generate_app.tar.gz"
Content-Type: application/gzip
#endif
char boundary[128] = {0};
char g_filepath[128] = {0};
static int find_content_start_pos(struct ezcfg_http *http, char *buf, int n)
{
  char filename[128] = {0};
  char *p, *p2;
  if ((p = ezcfg_http_get_header_value(http, EZCFG_HTTP_HEADER_CONTENT_TYPE)) != NULL) {
    //printf("content type [%s]\n", p);
    get_val(boundary, p, "boundary=", '\0');
    get_val(filename, buf, "filename=\"", '"');
    //printf("boundary [%s]\n", boundary);
    //printf("filename [%s]\n", filename);
    snprintf(g_filepath, sizeof(g_filepath), "%s/%s", DOWNLOAD_PATH, filename);
    if(strlen(boundary) > 0) {
      p2 = strstr(buf, boundary);
      if (p2) {
	p2 = strstr(buf, "\r\n\r\n");
	if (p2)
	  return p2 + strlen("\r\n\r\n") - buf;
      } else
        return -1;
    }
  }
  return -1;
}

static void save_http_content_to_file(char *buf, int n)
{
  FILE *fp = fopen(g_filepath, "w+");
  if (!fp) {
    printf("fopen(%s) error\n", g_filepath);
    return;
  }
  fwrite(buf, 1, n, fp);
  fclose(fp);
}

void local_socket_agent_worker_thread_process_http_new_connection(struct worker_thread_arg *arg)
{
  int header_len, nread;
  char *buf;
  int buf_len;
  struct ezcfg *ezcfg = NULL;
  struct ezcfg_socket_agent *agent = NULL;
  struct ezcfg_http *http = NULL;
  struct ezcfg_socket *sp = NULL;

  ASSERT(arg != NULL);
  agent = arg->agent;
  ezcfg = agent->ezcfg;
  sp = arg->sp;

  http = (struct ezcfg_http *)arg->proto_data;
  ASSERT(http != NULL);

  int bufsize = 4096;
  buf = calloc(1, bufsize);
  buf_len = 4096;
  nread = 0;
  header_len = ezcfg_socket_read_http_header(sp, http, buf, buf_len, &nread);

  ASSERT(nread >= header_len);

  if (header_len <= 0) {
    EZDBG("%s(%d) request error\n", __func__, __LINE__);
    err(ezcfg, "request error\n");
    free(buf);
    return; /* Request is too large or format is not correct */
  }

  /* 0-terminate the request: parse http request uses sscanf
   * !!! never, be careful not mangle the "\r\n\r\n" string!!!
   */
  //buf[header_len - 1] = '\0';
  ezcfg_http_set_state_request(http);
  if (ezcfg_http_parse_header(http, buf, header_len) == false) {
    printf("(%s:%d) imotom dump\n", __func__, __LINE__);
    EZDBG("%s(%d) Can not parse request: %s\n", __func__, __LINE__, buf);
    send_http_page(arg, 400, "Bad Request", "Can not parse request");//FIXME
    free(buf);
    return;
  }
  printf("recv 1[%s]\n", buf);
    ezcfg_http_dump(http);
    if (ezcfg_http_request_method_cmp(http, EZCFG_HTTP_METHOD_GET) == 0) {
        handle_http_request_get(arg, http);
        free(buf);
        return;
    } else if (ezcfg_http_request_method_cmp(http, EZCFG_HTTP_METHOD_POST) == 0) {
      char *uri = ezcfg_http_get_request_uri(http);
      arg->birth_time = time(NULL);
      printf("request_uri=[%s]\n", uri);
      if (strcmp(uri, "/web/login") == 0) {
        ezcfg_socket_read_http_content(sp, http, &buf, header_len, &buf_len, &nread);
        ezcfg_http_set_message_body(http, buf + header_len, nread - header_len);
        //printf("recv 2 nread %d, buf_len %d, header_len %d[%s]\n", nread, buf_len, header_len, buf);
        char page[128] = {0};
        memset(buf, 0, bufsize);
        snprintf(page, sizeof(page), "%s/firmware.html", WEB_PATH);
        get_file(buf, page);
	send_http_page(arg, 200, "OK", "%s", buf);
        free(buf);
	return;
      } else if (strcmp(uri, "/upload") == 0) {
        //printf("nread %d, buf_len %d, header_len %d\n", nread, buf_len, header_len);
        int start_pos = find_content_start_pos(http, buf + header_len, nread - header_len);
        if (start_pos < 0) {
	  send_http_page(arg, 400, "Bad Request", "Can not Handle");
          free(buf);
	  return;
        }
        //printf("start_pos %d\n", start_pos);
        save_http_content_to_file(buf + header_len + start_pos, nread - header_len - start_pos);
        EZDBG("%s(%d) saving %s\n", __func__, __LINE__, g_filepath);
        int filesize = ezcfg_socket_read_http_content_to_file(g_filepath, sp, http, boundary);
        printf("file %s %d\n", g_filepath, filesize + nread - header_len - start_pos);
	if (handle_http_request_post_upload(arg, http) == 0) {
          char page[128] = {0};
          snprintf(page, sizeof(page), "%s/upgrade.html", WEB_PATH);
          memset(buf, 0, bufsize);
          get_file(buf, page);
	  send_http_page(arg, 200, "OK", "%s", buf);
          free(buf);
	  return;
	} else {
	  send_http_page(arg, 400, "Bad Request", "Can not Handle");
          free(buf);
	  return;
        }
      }
    }
    free(buf);
    return;
}
