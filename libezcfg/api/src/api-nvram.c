/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 * ============================================================================
 * Project Name : ezcfg Application Programming Interface
 * Module Name  : api-nvram.c
 *
 * Description  : ezcfg API for nvram manipulate
 *
 * Copyright (C) 2008-2013 by ezbox-project
 *
 * History      Rev       Description
 * 2010-09-17   0.1       Write it from scratch
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
#include <sys/ipc.h>
#include <sys/sem.h>
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

#include "ezcfg.h"
#include "ezcfg-private.h"
#include "ezcfg-soap_http.h"

#include "ezcfg-api.h"

#if 0
#define DBG(format, args...) do {\
    FILE *dbg_fp = fopen("/tmp/api-nvram.log", "a");	\
    if (dbg_fp) {					\
      fprintf(dbg_fp, format, ## args);			\
      fclose(dbg_fp);					\
    }							\
  } while(0)
#else
#define DBG(format, args...)
#endif

static bool debug = false;

#if 0
static void
log_fn(struct ezcfg *ezcfg, int priority,
       const char *file, int line, const char *fn,
       const char *format, va_list args)
{
  if (debug) {
    char buf[1024];
    struct timeval tv;
    struct timezone tz;

    vsnprintf(buf, sizeof(buf), format, args);
    gettimeofday(&tv, &tz);
    fprintf(stderr, "%llu.%06u [%u] %s(%d): %s",
	    (unsigned long long) tv.tv_sec, (unsigned int) tv.tv_usec,
	    (int) getpid(), fn, line, buf);
  }
#if 0
  else {
    vsyslog(priority, format, args);
  }
#endif
}
#endif

/**
 * ezcfg_api_nvram_get:
 * @name: nvram name
 * @value: buffer to store nvram value
 * @len: buffer size
 *
 **/
int ezcfg_api_nvram_get(const char *name, char *value, size_t len)
{
#if 0
  char buf[1024];
  char *msg = NULL;
  int msg_len;
  struct ezcfg *ezcfg = NULL;
  struct ezcfg_ctrl *ezctrl = NULL;
  struct ezcfg_soap_http *sh = NULL;
  struct ezcfg_soap *soap = NULL;
  struct ezcfg_http *http = NULL;
  struct ezcfg_socket *sp = NULL;
  int body_index, child_index, getnv_index;
  char *res_name, *res_value;
  char *p;
  int header_len;
  int n;
  int rc = 0;
  int key, semid = -1;
  struct sembuf res;

  if (name == NULL || value == NULL || len < 1) {
    return -EZCFG_E_ARGUMENT ;
  }

  ezcfg = ezcfg_new(ezcfg_api_common_get_config_file());
  if (ezcfg == NULL) {
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

  ezcfg_log_init("nvram_get");
  ezcfg_common_set_log_func(ezcfg, log_fn);

  sh = ezcfg_soap_http_new(ezcfg);
  if (sh == NULL) {
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

  soap = ezcfg_soap_http_get_soap(sh);
  http = ezcfg_soap_http_get_http(sh);

  /* build HTTP request line */
  ezcfg_http_set_request_method(http, EZCFG_SOAP_HTTP_METHOD_GET);
  snprintf(buf, sizeof(buf), "%s?name=%s", EZCFG_SOAP_HTTP_NVRAM_GET_URI, name);
  ezcfg_http_set_request_uri(http, buf);
  ezcfg_http_set_version_major(http, 1);
  ezcfg_http_set_version_minor(http, 1);
  ezcfg_http_set_state_request(http);

  /* build HTTP headers */
  snprintf(buf, sizeof(buf), "%s", EZCFG_LOOPBACK_DEFAULT_IPADDR);
  ezcfg_http_add_header(http, EZCFG_SOAP_HTTP_HEADER_HOST, buf);
  snprintf(buf, sizeof(buf), "%s", "application/soap+xml");
  ezcfg_http_add_header(http, EZCFG_SOAP_HTTP_HEADER_ACCEPT, buf);

  n = ezcfg_soap_http_get_message_length(sh)+1; /* one more for 0-terminated */
  msg_len = (n > EZCFG_BUFFER_SIZE) ? n : EZCFG_BUFFER_SIZE;
  msg = (char *)malloc(msg_len);
  if (msg == NULL) {
    rc = -EZCFG_E_SPACE ;
    goto exit;
  }
  memset(msg, 0, msg_len);
  n = ezcfg_soap_http_write_message(sh, msg, msg_len);

  /* prepare semaphore */
  key = ftok(ezcfg_common_get_sem_ezcfg_path(ezcfg), EZCFG_SEM_PROJID_EZCFG);
  if (key == -1) {
    DBG("<6>pid=[%d] ftok error.\n", getpid());
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

  /* create a semaphore set */
  semid = semget(key, EZCFG_SEM_NUMBER, 00666);
  while (semid < 0) {
    DBG("<6>pid=[%d] try to create sem.\n", getpid());
    semid = semget(key, EZCFG_SEM_NUMBER, 00666);
  }

  /* now require available resource */
  res.sem_num = EZCFG_SEM_NVRAM_INDEX;
  res.sem_op = -1;
  res.sem_flg = 0;

  if (semop(semid, &res, 1) == -1) {
    DBG("<6>pid=[%d] semop require_res error\n", getpid());
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

  snprintf(buf, sizeof(buf), "%s-%d", ezcfg_common_get_sock_nvram_path(ezcfg), getpid());
  ezctrl = ezcfg_ctrl_new_from_socket(ezcfg, AF_LOCAL, EZCFG_PROTO_SOAP_HTTP, buf, ezcfg_common_get_sock_nvram_path(ezcfg));

  if (ezctrl == NULL) {
    rc = -EZCFG_E_RESOURCE ;
    goto sem_exit;
  }

  if (ezcfg_ctrl_connect(ezctrl) < 0) {
    rc = -EZCFG_E_CONNECTION ;
    goto sem_exit;
  }

  if (ezcfg_ctrl_write(ezctrl, msg, n, 0) < 0) {
    rc = -EZCFG_E_WRITE ;
    goto sem_exit;
  }

  ezcfg_soap_http_reset_attributes(sh);

  n = 0;
  sp = ezcfg_ctrl_get_socket(ezctrl);
  header_len = ezcfg_socket_read_http_header(sp, http, msg, msg_len, &n);

  if (header_len <= 0) {
    rc = -EZCFG_E_READ ;
    goto sem_exit;
  }

  ezcfg_http_set_state_response(http);
  if (ezcfg_soap_http_parse_header(sh, msg, header_len) == false) {
    rc = -EZCFG_E_PARSE ;
    goto sem_exit;
  }

  p = ezcfg_socket_read_http_content(sp, http, msg, header_len, &msg_len, &n);
  if ((p == NULL) || (n <= header_len)){
    rc = -EZCFG_E_READ ;
    goto sem_exit;
  }
  msg = p;

  ezcfg_soap_http_set_message_body(sh, msg + header_len, n - header_len);
  if (ezcfg_soap_http_parse_message_body(sh) == false) {
    rc = -EZCFG_E_PARSE ;
    goto sem_exit;
  }

  /* get getNvramResponse part */
  body_index = ezcfg_soap_get_body_index(soap);
  getnv_index = ezcfg_soap_get_element_index(soap, body_index, -1, EZCFG_SOAP_NVRAM_GETNV_RESPONSE_ELEMENT_NAME);
  if (getnv_index < 2) {
    rc = -EZCFG_E_PARSE ;
    goto sem_exit;
  }

  /* get nvram node name */
  child_index = ezcfg_soap_get_element_index(soap, getnv_index, -1, EZCFG_SOAP_NVRAM_NAME_ELEMENT_NAME);
  if (child_index < 2) {
    rc = -EZCFG_E_PARSE ;
    goto sem_exit;
  }

  res_name = ezcfg_soap_get_element_content_by_index(soap, child_index);
  if (res_name == NULL) {
    rc = -EZCFG_E_PARSE ;
    goto sem_exit;
  }

  /* get nvram entry value */
  child_index = ezcfg_soap_get_element_index(soap, getnv_index, -1, EZCFG_SOAP_NVRAM_VALUE_ELEMENT_NAME);
  if (child_index < 2) {
    rc = -EZCFG_E_PARSE ;
    goto sem_exit;
  }

  res_value = ezcfg_soap_get_element_content_by_index(soap, child_index);

  if (res_value == NULL) {
    /* nvram value is empty */
    res_value = "";
  }

  if (len < strlen(res_value)+1) {
    rc = -EZCFG_E_SPACE ;
    goto sem_exit;
  }

  rc = snprintf(value, len, "%s", res_value);

 sem_exit:
  /* now release resource */
  res.sem_num = EZCFG_SEM_NVRAM_INDEX;
  res.sem_op = 1;
  res.sem_flg = 0;

  if (semop(semid, &res, 1) == -1) {
    DBG("<6>pid=[%d] semop release_res error\n", getpid());
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

 exit:
  if (msg != NULL) {
    free(msg);
  }

  if (sh != NULL) {
    ezcfg_soap_http_delete(sh);
  }

  if (ezctrl != NULL) {
    ezcfg_ctrl_delete(ezctrl);
  }

  if (ezcfg != NULL) {
    ezcfg_delete(ezcfg);
  }

  return rc;
#else
  return 0;
#endif
}

/**
 * ezcfg_api_nvram_set:
 * @name: nvram name
 * @value: buffer stored nvram value
 *
 **/
int ezcfg_api_nvram_set(const char *name, const char *value)
{
#if 0
  char buf[1024];
  char *msg = NULL;
  int msg_len;
  struct ezcfg *ezcfg = NULL;
  struct ezcfg_ctrl *ezctrl = NULL;
  struct ezcfg_soap_http *sh = NULL;
  struct ezcfg_soap *soap = NULL;
  struct ezcfg_http *http = NULL;
  struct ezcfg_socket *sp = NULL;
  int body_index, child_index, setnv_index;
  char *result;
  char *p;
  int header_len;
  int n;
  int rc = 0;
  int key, semid = -1;
  struct sembuf res;

  if (name == NULL || value == NULL) {
    return -EZCFG_E_ARGUMENT ;
  }

  ezcfg = ezcfg_new(ezcfg_api_common_get_config_file());
  if (ezcfg == NULL) {
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

  ezcfg_log_init("nvram_set");
  ezcfg_common_set_log_fn(ezcfg, log_fn);

  sh = ezcfg_soap_http_new(ezcfg);
  if (sh == NULL) {
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

  soap = ezcfg_soap_http_get_soap(sh);
  http = ezcfg_soap_http_get_http(sh);

  /* build SOAP */
  ezcfg_soap_set_version_major(soap, 1);
  ezcfg_soap_set_version_minor(soap, 2);

  /* SOAP Envelope */
  ezcfg_soap_set_envelope(soap, EZCFG_SOAP_ENVELOPE_ELEMENT_NAME);
  ezcfg_soap_add_envelope_attribute(soap, EZCFG_SOAP_ENVELOPE_ATTR_NS_NAME, EZCFG_SOAP_ENVELOPE_ATTR_NS_VALUE, EZCFG_XML_ELEMENT_ATTRIBUTE_TAIL);

  /* SOAP Body */
  body_index = ezcfg_soap_set_body(soap, EZCFG_SOAP_BODY_ELEMENT_NAME);

  /* Body child setNvram part */
  setnv_index = ezcfg_soap_add_body_child(soap, body_index, -1, EZCFG_SOAP_NVRAM_SETNV_ELEMENT_NAME, NULL);
  ezcfg_soap_add_body_child_attribute(soap, setnv_index, EZCFG_SOAP_NVRAM_ATTR_NS_NAME, EZCFG_SOAP_NVRAM_ATTR_NS_VALUE, EZCFG_XML_ELEMENT_ATTRIBUTE_TAIL);

  child_index = -1;
  /* nvram name part */
  child_index = ezcfg_soap_add_body_child(soap, setnv_index, child_index, EZCFG_SOAP_NVRAM_NAME_ELEMENT_NAME, name);

  /* nvram value part */
  child_index = ezcfg_soap_add_body_child(soap, setnv_index, child_index, EZCFG_SOAP_NVRAM_VALUE_ELEMENT_NAME, value);

  /* build HTTP message body */
  msg_len = ezcfg_soap_get_message_length(soap);
  msg_len += strlen("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
  msg_len++; /* '\n' */
  msg_len++; /* '\0' */
  msg = (char *)malloc(msg_len);
  if (msg == NULL) {
    rc = -EZCFG_E_SPACE ;
    goto exit;
  }
  memset(msg, 0, msg_len);

  snprintf(msg, msg_len, "%s\n", "<?xml version=\"1.0\" encoding=\"utf-8\"?>");
  n = strlen(msg);
  n += ezcfg_soap_write_message(soap, msg + n, msg_len - n);
  ezcfg_http_set_message_body(http, msg, n);

  /* build HTTP request line */
  ezcfg_http_set_request_method(http, EZCFG_SOAP_HTTP_METHOD_POST);
  snprintf(buf, sizeof(buf), "%s", EZCFG_SOAP_HTTP_NVRAM_SET_URI);
  ezcfg_http_set_request_uri(http, buf);
  ezcfg_http_set_version_major(http, 1);
  ezcfg_http_set_version_minor(http, 1);
  ezcfg_http_set_state_request(http);

  /* build HTTP headers */
  snprintf(buf, sizeof(buf), "%s", EZCFG_LOOPBACK_DEFAULT_IPADDR);
  ezcfg_http_add_header(http, EZCFG_SOAP_HTTP_HEADER_HOST, buf);
  snprintf(buf, sizeof(buf), "%s", "application/soap+xml");
  ezcfg_http_add_header(http, EZCFG_SOAP_HTTP_HEADER_ACCEPT, buf);

  msg_len = ezcfg_soap_http_get_message_length(sh);
  p = (char *)realloc(msg, msg_len);
  if (p == NULL) {
    rc = -EZCFG_E_SPACE ;
    goto exit;
  }
  msg = p;
  memset(msg, 0, msg_len);
  n = ezcfg_soap_http_write_message(sh, msg, msg_len);

  /* prepare semaphore */
  key = ftok(ezcfg_common_get_sem_ezcfg_path(ezcfg), EZCFG_SEM_PROJID_EZCFG);
  if (key == -1) {
    DBG("<6>pid=[%d] ftok error.\n", getpid());
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

  /* create a semaphore set */
  semid = semget(key, EZCFG_SEM_NUMBER, 00666);
  while (semid < 0) {
    DBG("<6>pid=[%d] try to create sem.\n", getpid());
    semid = semget(key, EZCFG_SEM_NUMBER, 00666);
  }

  /* now require available resource */
  res.sem_num = EZCFG_SEM_NVRAM_INDEX;
  res.sem_op = -1;
  res.sem_flg = 0;

  if (semop(semid, &res, 1) == -1) {
    DBG("<6>pid=[%d] semop require_res error\n", getpid());
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

  snprintf(buf, sizeof(buf), "%s-%d", ezcfg_common_get_sock_nvram_path(ezcfg), getpid());
  ezctrl = ezcfg_ctrl_new_from_socket(ezcfg, AF_LOCAL, EZCFG_PROTO_SOAP_HTTP, buf, ezcfg_common_get_sock_nvram_path(ezcfg));

  if (ezctrl == NULL) {
    rc = -EZCFG_E_RESOURCE ;
    goto sem_exit;
  }

  if (ezcfg_ctrl_connect(ezctrl) < 0) {
    rc = -EZCFG_E_CONNECTION ;
    goto sem_exit;
  }

  if (ezcfg_ctrl_write(ezctrl, msg, msg_len, 0) < 0) {
    rc = -EZCFG_E_WRITE ;
    goto sem_exit;
  }

  ezcfg_soap_http_reset_attributes(sh);

  n = 0;
  sp = ezcfg_ctrl_get_socket(ezctrl);
  header_len = ezcfg_socket_read_http_header(sp, http, msg, msg_len, &n);

  if (header_len <= 0) {
    rc = -EZCFG_E_READ ;
    goto sem_exit;
  }

  ezcfg_http_set_state_response(http);
  if (ezcfg_soap_http_parse_header(sh, msg, header_len) == false) {
    rc = -EZCFG_E_PARSE ;
    goto sem_exit;
  }

  p = ezcfg_socket_read_http_content(sp, http, msg, header_len, &msg_len, &n);
  if ((p == NULL) || (n <= header_len)){
    rc = -EZCFG_E_READ ;
    goto sem_exit;
  }
  msg = p;

  ezcfg_soap_http_set_message_body(sh, msg + header_len, n - header_len);
  if (ezcfg_soap_http_parse_message_body(sh) == false) {
    rc = -EZCFG_E_PARSE ;
    goto sem_exit;
  }

  /* get setNvramResponse part */
  body_index = ezcfg_soap_get_body_index(soap);
  setnv_index = ezcfg_soap_get_element_index(soap, body_index, -1, EZCFG_SOAP_NVRAM_SETNV_RESPONSE_ELEMENT_NAME);
  if (setnv_index < 2) {
    rc = -EZCFG_E_PARSE ;
    goto sem_exit;
  }

  /* get nvram result part */
  child_index = ezcfg_soap_get_element_index(soap, setnv_index, -1, EZCFG_SOAP_NVRAM_RESULT_ELEMENT_NAME);
  if (child_index < 2) {
    rc = -EZCFG_E_PARSE ;
    goto sem_exit;
  }

  result = ezcfg_soap_get_element_content_by_index(soap, child_index);
  if (result == NULL) {
    rc = -EZCFG_E_RESULT ;
    goto sem_exit;
  }

  if (strcmp(result, EZCFG_SOAP_NVRAM_RESULT_VALUE_OK) == 0) {
    rc = 0;
  }
  else {
    rc = -EZCFG_E_RESULT ;
  }

 sem_exit:
  /* now release resource */
  res.sem_num = EZCFG_SEM_NVRAM_INDEX;
  res.sem_op = 1;
  res.sem_flg = 0;

  if (semop(semid, &res, 1) == -1) {
    DBG("<6>pid=[%d] semop release_res error\n", getpid());
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

 exit:
  if (msg != NULL) {
    free(msg);
  }

  if (sh != NULL) {
    ezcfg_soap_http_delete(sh);
  }

  if (ezctrl != NULL) {
    ezcfg_ctrl_delete(ezctrl);
  }

  if (ezcfg != NULL) {
    ezcfg_delete(ezcfg);
  }

  return rc;
#else
  return 0;
#endif
}

/**
 * ezcfg_api_nvram_unset:
 * @name: nvram name
 *
 **/
int ezcfg_api_nvram_unset(const char *name)
{
#if 0
  char buf[1024];
  char *msg = NULL;
  int msg_len;
  struct ezcfg *ezcfg = NULL;
  struct ezcfg_ctrl *ezctrl = NULL;
  struct ezcfg_soap_http *sh = NULL;
  struct ezcfg_soap *soap = NULL;
  struct ezcfg_http *http = NULL;
  struct ezcfg_socket *sp = NULL;
  int body_index, child_index, unsetnv_index;
  char *result;
  char *p;
  int header_len;
  int n;
  int rc = 0;
  int key, semid = -1;
  struct sembuf res;

  if (name == NULL) {
    return -EZCFG_E_ARGUMENT ;
  }

  ezcfg = ezcfg_new(ezcfg_api_common_get_config_file());
  if (ezcfg == NULL) {
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

  ezcfg_log_init("nvram_unset");
  ezcfg_common_set_log_fn(ezcfg, log_fn);

  sh = ezcfg_soap_http_new(ezcfg);
  if (sh == NULL) {
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

  soap = ezcfg_soap_http_get_soap(sh);
  http = ezcfg_soap_http_get_http(sh);

  /* build HTTP request line */
  ezcfg_http_set_request_method(http, EZCFG_SOAP_HTTP_METHOD_GET);
  snprintf(buf, sizeof(buf), "%s?name=%s", EZCFG_SOAP_HTTP_NVRAM_UNSET_URI, name);
  ezcfg_http_set_request_uri(http, buf);
  ezcfg_http_set_version_major(http, 1);
  ezcfg_http_set_version_minor(http, 1);
  ezcfg_http_set_state_request(http);

  /* build HTTP headers */
  snprintf(buf, sizeof(buf), "%s", EZCFG_LOOPBACK_DEFAULT_IPADDR);
  ezcfg_http_add_header(http, EZCFG_SOAP_HTTP_HEADER_HOST, buf);
  snprintf(buf, sizeof(buf), "%s", "application/soap+xml");
  ezcfg_http_add_header(http, EZCFG_SOAP_HTTP_HEADER_ACCEPT, buf);

  n = ezcfg_soap_http_get_message_length(sh)+1; /* one more for 0-terminated */
  msg_len = (n > EZCFG_BUFFER_SIZE) ? n : EZCFG_BUFFER_SIZE;
  msg = (char *)malloc(msg_len);
  if (msg == NULL) {
    rc = -EZCFG_E_SPACE ;
    goto exit;
  }
  memset(msg, 0, msg_len);
  n = ezcfg_soap_http_write_message(sh, msg, msg_len);

  /* prepare semaphore */
  key = ftok(ezcfg_common_get_sem_ezcfg_path(ezcfg), EZCFG_SEM_PROJID_EZCFG);
  if (key == -1) {
    DBG("<6>pid=[%d] ftok error.\n", getpid());
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

  /* create a semaphore set */
  semid = semget(key, EZCFG_SEM_NUMBER, 00666);
  while (semid < 0) {
    DBG("<6>pid=[%d] try to create sem.\n", getpid());
    semid = semget(key, EZCFG_SEM_NUMBER, 00666);
  }

  /* now require available resource */
  res.sem_num = EZCFG_SEM_NVRAM_INDEX;
  res.sem_op = -1;
  res.sem_flg = 0;

  if (semop(semid, &res, 1) == -1) {
    DBG("<6>pid=[%d] semop require_res error\n", getpid());
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

  snprintf(buf, sizeof(buf), "%s-%d", ezcfg_common_get_sock_nvram_path(ezcfg), getpid());
  ezctrl = ezcfg_ctrl_new_from_socket(ezcfg, AF_LOCAL, EZCFG_PROTO_SOAP_HTTP, buf, ezcfg_common_get_sock_nvram_path(ezcfg));

  if (ezctrl == NULL) {
    rc = -EZCFG_E_RESOURCE ;
    goto sem_exit;
  }

  if (ezcfg_ctrl_connect(ezctrl) < 0) {
    rc = -EZCFG_E_CONNECTION ;
    goto sem_exit;
  }

  if (ezcfg_ctrl_write(ezctrl, msg, n, 0) < 0) {
    rc = -EZCFG_E_WRITE ;
    goto sem_exit;
  }

  ezcfg_soap_http_reset_attributes(sh);

  n = 0;
  sp = ezcfg_ctrl_get_socket(ezctrl);
  header_len = ezcfg_socket_read_http_header(sp, http, msg, msg_len, &n);

  if (header_len <= 0) {
    rc = -EZCFG_E_READ ;
    goto sem_exit;
  }

  ezcfg_http_set_state_response(http);
  if (ezcfg_soap_http_parse_header(sh, msg, header_len) == false) {
    rc = -EZCFG_E_PARSE ;
    goto sem_exit;
  }

  p = ezcfg_socket_read_http_content(sp, http, msg, header_len, &msg_len, &n);
  if ((p == NULL) || (n <= header_len)){
    rc = -EZCFG_E_READ ;
    goto sem_exit;
  }
  msg = p;

  ezcfg_soap_http_set_message_body(sh, msg + header_len, n - header_len);
  if (ezcfg_soap_http_parse_message_body(sh) == false) {
    rc = -EZCFG_E_PARSE ;
    goto sem_exit;
  }

  /* get unsetNvramResponse part */
  body_index = ezcfg_soap_get_body_index(soap);
  unsetnv_index = ezcfg_soap_get_element_index(soap, body_index, -1, EZCFG_SOAP_NVRAM_UNSETNV_RESPONSE_ELEMENT_NAME);
  if (unsetnv_index < 2) {
    rc = -EZCFG_E_PARSE ;
    goto sem_exit;
  }

  /* get nvram result part */
  child_index = ezcfg_soap_get_element_index(soap, unsetnv_index, -1, EZCFG_SOAP_NVRAM_RESULT_ELEMENT_NAME);
  if (child_index < 2) {
    rc = -EZCFG_E_PARSE ;
    goto sem_exit;
  }

  result = ezcfg_soap_get_element_content_by_index(soap, child_index);
  if (result == NULL) {
    rc = -EZCFG_E_RESULT ;
    goto sem_exit;
  }

  if (strcmp(result, EZCFG_SOAP_NVRAM_RESULT_VALUE_OK) == 0) {
    rc = 0;
  }
  else {
    rc = -EZCFG_E_RESULT ;
  }

 sem_exit:
  /* now release resource */
  res.sem_num = EZCFG_SEM_NVRAM_INDEX;
  res.sem_op = 1;
  res.sem_flg = 0;

  if (semop(semid, &res, 1) == -1) {
    DBG("<6>pid=[%d] semop release_res error\n", getpid());
    rc = -EZCFG_E_RESOURCE ;
    goto exit;
  }

 exit:
  if (msg != NULL) {
    free(msg);
  }

  if (sh != NULL) {
    ezcfg_soap_http_delete(sh);
  }

  if (ezctrl != NULL) {
    ezcfg_ctrl_delete(ezctrl);
  }

  if (ezcfg != NULL) {
    ezcfg_delete(ezcfg);
  }

  return rc;
#else
  return 0;
#endif
}

void ezcfg_api_nvram_set_debug(bool enable_debug)
{
  debug = enable_debug;
}
