/* ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : ezcfg-json_http.h
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2014 by ezbox-project
 *
 * History      Rev       Description
 * 2014-03-14   0.1       Write it from scratch
 * ============================================================================
 */

#ifndef _EZCFG_JSON_HTTP_H_
#define _EZCFG_JSON_HTTP_H_

#include "ezcfg.h"
#include "ezcfg-http.h"

struct ezcfg_json_http {
	struct ezcfg *ezcfg;
	struct ezcfg_http *http;
	struct ezcfg_json *json;
};

/* json/json_http_nvram.c */
int ezcfg_json_http_handle_nvram_request(struct ezcfg_json_http *jh, struct ezcfg_nvram *nvram);

/* ezcfg JSON over HTTP http methods */
#define EZCFG_JSON_HTTP_METHOD_GET          "GET"
#define EZCFG_JSON_HTTP_METHOD_POST         "POST"
/* ezcfg JSON over HTTP http headers */
#define EZCFG_JSON_HTTP_HEADER_HOST                 "Host"
#define EZCFG_JSON_HTTP_HEADER_CONTENT_TYPE         "Content-Type"
#define EZCFG_JSON_HTTP_HEADER_CONTENT_LENGTH       "Content-Length"
#define EZCFG_JSON_HTTP_HEADER_ACCEPT               "Accept"
/* ezcfg NVRAM on JSON over HTTP handler */
#define EZCFG_JSON_HTTP_NVRAM_URI                   "/ezcfg/nvram/json"

/* ezcfg JSON over HTTP socket handler */

#endif
