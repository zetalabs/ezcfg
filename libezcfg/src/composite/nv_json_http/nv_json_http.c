/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 * ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : composite/nv_json_http/nv_json_http.c
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2016 by ezbox-project
 *
 * History      Rev       Description
 * 2015-12-29   0.1       Write it from scratch
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pthread.h>

#include "ezcfg.h"
#include "ezcfg-private.h"
#include "ezcfg-priv_composite_nv_json_http.h"

struct ezcfg_nv_json_http {
  struct ezcfg *ezcfg;
  struct ezcfg_http *http;
  struct ezcfg_json *json;
  struct ezcfg_nv_linked_list *nv_list;
};

/* for JSON/HTTP binding request methods */
static const char *nv_json_http_method_strings[] = {
  /* bad method string */
  NULL ,
  /* JSON over HTTP used methods */
  EZCFG_HTTP_METHOD_POST ,
};

/* for JSON over HTTP binding known header */
static const char *nv_json_http_header_strings[] = {
  /* bad header string */
  NULL ,
  /* JSON over HTTP binding known headers */
  EZCFG_HTTP_HEADER_HOST ,
  EZCFG_HTTP_HEADER_CONTENT_TYPE ,
  EZCFG_HTTP_HEADER_CONTENT_LENGTH ,
};

/**
 * Public functions
 **/
int ezcfg_nv_json_http_del(struct ezcfg_nv_json_http *njh)
{
  //struct ezcfg *ezcfg;

  ASSERT(njh != NULL);

  //ezcfg = sh->ezcfg;

  if (njh->json != NULL)
    ezcfg_json_del(njh->json);

  if (njh->http != NULL)
    ezcfg_http_del(njh->http);

  if (njh->nv_list != NULL)
    ezcfg_nv_linked_list_del(njh->nv_list);

  free(njh);
  return EZCFG_RET_OK;
}

/**
 * ezcfg_nv_json_http_new:
 * Create ezcfg NVRAM/JSON over HTTP info builder data structure
 * Returns: a new ezcfg nvram/json http binding info builder data structure
 **/
struct ezcfg_nv_json_http *ezcfg_nv_json_http_new(struct ezcfg *ezcfg)
{
  struct ezcfg_nv_json_http *njh;

  ASSERT(ezcfg != NULL);

  /* initialize nvram json http binding info builder data structure */
  njh = calloc(1, sizeof(struct ezcfg_nv_json_http));
  if (njh == NULL) {
    err(ezcfg, "initialize nvram/json http binding builder error.\n");
    return NULL;
  }

  njh->json = ezcfg_json_new(ezcfg);
  if (njh->json == NULL) {
    ezcfg_nv_json_http_del(njh);
    return NULL;
  }

  njh->http = ezcfg_http_new(ezcfg);
  if (njh->http == NULL) {
    ezcfg_nv_json_http_del(njh);
    return NULL;
  }

  njh->nv_list = ezcfg_nv_linked_list_new(ezcfg);
  if (njh->nv_list == NULL) {
    ezcfg_nv_json_http_del(njh);
    return NULL;
  }

  njh->ezcfg = ezcfg;
  ezcfg_http_set_method_strings(njh->http, nv_json_http_method_strings, ARRAY_SIZE(nv_json_http_method_strings) - 1);
  ezcfg_http_set_known_header_strings(njh->http, nv_json_http_header_strings, ARRAY_SIZE(nv_json_http_header_strings) - 1);

  return njh;
}

unsigned short ezcfg_nv_json_http_get_http_version_major(struct ezcfg_nv_json_http *njh)
{
  //struct ezcfg *ezcfg;

  ASSERT(njh != NULL);
  ASSERT(njh->http != NULL);

  //ezcfg = njh->ezcfg;

  return ezcfg_http_get_version_major(njh->http);
}

unsigned short ezcfg_nv_json_http_get_http_version_minor(struct ezcfg_nv_json_http *njh)
{
  //struct ezcfg *ezcfg;

  ASSERT(njh != NULL);
  ASSERT(njh->http != NULL);

  //ezcfg = njh->ezcfg;

  return ezcfg_http_get_version_minor(njh->http);
}

bool ezcfg_nv_json_http_set_http_version_major(struct ezcfg_nv_json_http *njh, unsigned short major)
{
  //struct ezcfg *ezcfg;

  ASSERT(njh != NULL);
  ASSERT(njh->http != NULL);

  //ezcfg = njh->ezcfg;

  return ezcfg_http_set_version_major(njh->http, major);
}

bool ezcfg_nv_json_http_set_http_version_minor(struct ezcfg_nv_json_http *njh, unsigned short minor)
{
  //struct ezcfg *ezcfg;

  ASSERT(njh != NULL);
  ASSERT(njh->http != NULL);

  //ezcfg = njh->ezcfg;

  return ezcfg_http_set_version_minor(njh->http, minor);
}

struct ezcfg_json *ezcfg_nv_json_http_get_json(struct ezcfg_nv_json_http *njh)
{
  //struct ezcfg *ezcfg;

  ASSERT(njh != NULL);
  ASSERT(njh->json != NULL);

  //ezcfg = njh->ezcfg;

  return njh->json;
}

struct ezcfg_http *ezcfg_nv_json_http_get_http(struct ezcfg_nv_json_http *njh)
{
  //struct ezcfg *ezcfg;

  ASSERT(njh != NULL);
  ASSERT(njh->http != NULL);

  //ezcfg = njh->ezcfg;

  return njh->http;
}

char *ezcfg_nv_json_http_get_http_header_value(struct ezcfg_nv_json_http *njh, char *name)
{
  //struct ezcfg *ezcfg;

  ASSERT(njh != NULL);
  ASSERT(njh->http != NULL);

  //ezcfg = njh->ezcfg;

  return ezcfg_http_get_header_value(njh->http, name);
}

int ezcfg_nv_json_http_reset_attributes(struct ezcfg_nv_json_http *njh)
{
  //struct ezcfg *ezcfg;

  ASSERT(njh != NULL);
  ASSERT(njh->http != NULL);
  ASSERT(njh->json != NULL);
  ASSERT(njh->nv_list != NULL);

  //ezcfg = njh->ezcfg;

  ezcfg_http_reset_attributes(njh->http);
  ezcfg_json_reset(njh->json);
  ezcfg_nv_linked_list_clr(njh->nv_list);

  return EZCFG_RET_OK;
}

int ezcfg_nv_json_http_dump(struct ezcfg_nv_json_http *njh)
{
  //struct ezcfg *ezcfg;

  ASSERT(njh != NULL);

  //ezcfg = njh->ezcfg;
  return EZCFG_RET_OK;
}

bool ezcfg_nv_json_http_parse_header(struct ezcfg_nv_json_http *njh, char *buf, int len)
{
  //struct ezcfg *ezcfg;
  struct ezcfg_http *http;

  ASSERT(njh != NULL);
  ASSERT(njh->http != NULL);

  //ezcfg = njh->ezcfg;
  http = njh->http;

  if (ezcfg_http_parse_header(http, buf, len) == false) {
    return false;
  }

  return true;
}

bool ezcfg_nv_json_http_parse_message_body(struct ezcfg_nv_json_http *njh)
{
  //struct ezcfg *ezcfg;
  struct ezcfg_http *http;
  struct ezcfg_json *json;
  char *msg_body;
  int msg_body_len;

  ASSERT(njh != NULL);
  ASSERT(njh->http != NULL);
  ASSERT(njh->json != NULL);

  //ezcfg = njh->ezcfg;
  http = njh->http;
  json = njh->json;

  msg_body = ezcfg_http_get_message_body(http);
  msg_body_len = ezcfg_http_get_message_body_len(http);

  if (msg_body != NULL && msg_body_len > 0) {
    if (ezcfg_json_parse_text(json, msg_body, msg_body_len) == EZCFG_RET_FAIL) {
      return false;
    }
  }

  return true;
}

char *ezcfg_nv_json_http_set_message_body(struct ezcfg_nv_json_http *njh, const char *body, const int len)
{
  //struct ezcfg *ezcfg;
  struct ezcfg_http *http;

  ASSERT(njh != NULL);
  ASSERT(njh->http != NULL);

  //ezcfg = njh->ezcfg;
  http = njh->http;

  return ezcfg_http_set_message_body(http, body, len);
}

int ezcfg_nv_json_http_get_message_length(struct ezcfg_nv_json_http *njh)
{
  //struct ezcfg *ezcfg;
  struct ezcfg_http *http;

  int n, count;

  ASSERT(njh != NULL);
  ASSERT(njh->http != NULL);

  //ezcfg = njh->ezcfg;
  http = njh->http;

  count = 0;
  n = ezcfg_http_get_start_line_length(http);
  if (n < 0) {
    return -1;
  }
  count += n;

  n = ezcfg_http_get_headers_length(http);
  if (n < 0) {
    return -1;
  }
  count += n;

  n = ezcfg_http_get_crlf_length(http);
  if (n < 0) {
    return -1;
  }
  count += n;

  n = ezcfg_http_get_message_body_len(http);
  if (n < 0) {
    return -1;
  }
  count += n;
  return count;
}

int ezcfg_nv_json_http_write_message(struct ezcfg_nv_json_http *njh, char *buf, int len)
{
  struct ezcfg *ezcfg;
  struct ezcfg_http *http;
  //struct ezcfg_json *json;

  char *p;
  int n;

  ASSERT(njh != NULL);
  ASSERT(njh->http != NULL);
  ASSERT(njh->json != NULL);
  ASSERT(buf != NULL);
  ASSERT(len > 0);

  ezcfg = njh->ezcfg;
  http = njh->http;
  //json= njh->json;

  p = buf;
  n = ezcfg_http_write_start_line(http, p, len);
  if (n < 0) {
    err(ezcfg, "ezcfg_http_write_start_line\n");
    return n;
  }
  p += n;
  len -= n;

  n = ezcfg_http_write_headers(http, p, len);
  if (n < 0) {
    err(ezcfg, "ezcfg_http_write_headers\n");
    return n;
  }
  p += n;
  len -= n;

  n = ezcfg_http_write_crlf(http, p, len);
  if (n < 0) {
    err(ezcfg, "ezcfg_http_write_crlf\n");
    return n;
  }
  p += n;
  len -= n;

  if (ezcfg_http_get_message_body(http) != NULL) {
    n = ezcfg_http_write_message_body(http, p, len);
    if (n < 0) {
      err(ezcfg, "ezcfg_http_write_message_body\n");
      return n;
    }
    p += n;
  }

  return (p-buf);
}
