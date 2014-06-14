/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 * ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : ezcfg-priv_json.h
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2014 by ezbox-project
 *
 * History      Rev       Description
 * 2014-03-08   0.1       Write it from scratch
 * ============================================================================
 */

#ifndef _EZCFG_PRIV_JSON_H_
#define _EZCFG_PRIV_JSON_H_

#include "ezcfg-types.h"

/* json/json.c */
struct ezcfg_json_value *ezcfg_json_value_create(char *buf);
int ezcfg_json_value_delete(struct ezcfg_json_value *vp);
int ezcfg_json_value_delete_wrap(void *data);

void ezcfg_json_reset(struct ezcfg_json *json);
void ezcfg_json_delete(struct ezcfg_json *json);
struct ezcfg_json *ezcfg_json_new(struct ezcfg *ezcfg);
int ezcfg_json_get_text_type(struct ezcfg_json *json);
bool ezcfg_json_parse_text(struct ezcfg_json *json, char *text, int len);
int ezcfg_json_get_msg_len(struct ezcfg_json *json);
int ezcfg_json_write_message(struct ezcfg_json *json, char *buf, int len);
struct ezcfg_linked_list *ezcfg_json_build_nvram_node_list(struct ezcfg_json *json);
bool ezcfg_json_is_nvram_representation(struct ezcfg_json *json);

#endif /* _EZCFG_PRIV_JSON_H_ */
