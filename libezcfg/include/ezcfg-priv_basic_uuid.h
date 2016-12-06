/* ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : ezcfg-priv_basic_uuid.h
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2014 by ezbox-project
 *
 * History      Rev       Description
 * 2016-01-10   0.1       Modify it from bak/uuid/uuid.c
 * ============================================================================
 */

#ifndef _EZCFG_PRIV_BASIC_UUID_H_
#define _EZCFG_PRIV_BASIC_UUID_H_

#include "ezcfg-types.h"

/* basic/uuid/uuid.c */
struct ezcfg_uuid *ezcfg_uuid_new(struct ezcfg *ezcfg, char *ns);
int ezcfg_uuid_del(struct ezcfg_uuid *uuid);

int ezcfg_uuid_get_version(struct ezcfg_uuid *uuid, int *pver);
int ezcfg_uuid_export_str(struct ezcfg_uuid *uuid, char *buf, int len);
int ezcfg_uuid_generate(struct ezcfg_uuid *uuid);

#endif /* _EZCFG_PRIV_BASIC_UUID_H_ */
