/* ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : ezcfg-priv_basic_process.h
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2014 by ezbox-project
 *
 * History      Rev       Description
 * 2015-06-11   0.1       Write it from scratch
 * ============================================================================
 */

#ifndef _EZCFG_PRIV_BASIC_PROCESS_H_
#define _EZCFG_PRIV_BASIC_PROCESS_H_

#include "ezcfg-types.h"

/* basic/process/process.c */
struct ezcfg_process *ezcfg_process_new(struct ezcfg *ezcfg, char *ns);
int ezcfg_process_del(struct ezcfg_process *process);
int ezcfg_process_stop(struct ezcfg_process *process, int sig);

int ezcfg_process_state_set_stopped(struct ezcfg_process *process);
int ezcfg_process_state_is_stopped(struct ezcfg_process *process);
int ezcfg_process_proc_has_no_process(struct ezcfg_process *process);

int ezcfg_process_del_handler(void *data);
int ezcfg_process_cmp_handler(const void *d1, const void *d2);

#endif /* _EZCFG_PRIV_BASIC_THREAD_H_ */
