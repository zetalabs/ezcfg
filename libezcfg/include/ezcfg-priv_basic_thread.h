/* ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : ezcfg-priv_basic_thread.h
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2014 by ezbox-project
 *
 * History      Rev       Description
 * 2015-06-10   0.1       Write it from scratch
 * ============================================================================
 */

#ifndef _EZCFG_PRIV_BASIC_THREAD_H_
#define _EZCFG_PRIV_BASIC_THREAD_H_

#include "ezcfg-types.h"

/* basic/thread/thread.c */
struct ezcfg_thread *ezcfg_thread_new(struct ezcfg *ezcfg, char *ns);
int ezcfg_thread_clr(struct ezcfg_thread *thread);
int ezcfg_thread_del(struct ezcfg_thread *thread);

int ezcfg_thread_set_start_routine(struct ezcfg_thread *thread, void *(*func)(void *), void *arg);
int ezcfg_thread_set_arg(struct ezcfg_thread *thread, void *arg);
int ezcfg_thread_set_arg_del_handler(struct ezcfg_thread *thread, int (*func)(void *));
int ezcfg_thread_set_stop(struct ezcfg_thread *thread, int (*func)(void *));
int ezcfg_thread_start(struct ezcfg_thread *thread);
int ezcfg_thread_stop(struct ezcfg_thread *thread);
int ezcfg_thread_kill(struct ezcfg_thread *thread, int sig);

int ezcfg_thread_state_is_running(struct ezcfg_thread *thread);
int ezcfg_thread_state_is_stopped(struct ezcfg_thread *thread);

int ezcfg_thread_del_handler(void *data);
int ezcfg_thread_cmp_handler(const void *d1, const void *d2);

#endif /* _EZCFG_PRIV_BASIC_THREAD_H_ */
