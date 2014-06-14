/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 * ============================================================================
 * Project Name : ezcfg Application Programming Interface
 * Module Name  : api-agent.c
 *
 * Description  : ezcfg API for ezcfg agent manipulate
 *
 * Copyright (C) 2008-2013 by ezbox-project
 *
 * History      Rev       Description
 * 2013-08-01   0.1       Modify it from api-master.c
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
    FILE *dbg_fp = fopen("/dev/kmsg", "a");	\
    if (dbg_fp) {				  \
      fprintf(dbg_fp, format, ## args);		  \
      fclose(dbg_fp);				  \
    }						  \
  } while(0)
#else
#define DBG(format, args...)
#endif

static bool debug = false;
static int
log_func(struct ezcfg *ezcfg,
	 int priority,
	 const char *file,
	 int line,
	 const char *func,
	 const char *format,
	 va_list args)
{
  char log_file[EZCFG_PATH_MAX];
  int ret;

  if (debug == false) {
    return EZCFG_RET_OK;
  }

  ret = ezcfg_common_get_log_file(ezcfg, log_file, sizeof(log_file));
  if (ret == EZCFG_RET_BAD) {
    return EZCFG_RET_BAD;
  }

  if (log_file[0] == '\0') {
    fprintf(stderr, "libezcfg: %s(%d)@%s: ", file, line, func);
    vfprintf(stderr, format, args);
    return EZCFG_RET_OK;
  }
  else {
    FILE *fp = fopen(log_file, "a");
    if (fp != NULL) {
      fprintf(fp, "libezcfg: %s(%d)@%s: ", file, line, func);
      vfprintf(fp, format, args);
      fclose(fp);
      return EZCFG_RET_OK;
    }
    else {
      return EZCFG_RET_BAD;
    }
  }
}

/**
 * ezcfg_api_agent_start:
 * @argv: nvram name
 * @value: buffer to store nvram value
 * @len: buffer size
 *
 **/
struct ezcfg_agent *ezcfg_api_agent_start(const char *name, int threads_max)
{
  struct ezcfg *ezcfg = NULL;
  struct ezcfg_agent *agent = NULL;

  if (name == NULL || threads_max < EZCFG_THREAD_MIN_NUM) {
    //return -EZCFG_E_ARGUMENT ;
    return NULL;
  }

  ezcfg = ezcfg_new(ezcfg_api_common_get_config_file());
  if (ezcfg == NULL) {
    //return -EZCFG_E_RESOURCE ;
    return NULL;
  }

  ezcfg_log_init(name);
  ezcfg_common_set_log_func(ezcfg, log_func);

  agent = ezcfg_agent_start(ezcfg);
  if (agent == NULL) {
    ezcfg_delete(ezcfg);
    return NULL;
  }

  ezcfg_agent_set_threads_max(agent, threads_max);

  return agent;
}

int ezcfg_api_agent_stop(struct ezcfg_agent *agent)
{
  if (agent == NULL) {
    return -EZCFG_E_ARGUMENT ;
  }

  ezcfg_agent_stop(agent);
  return 0;
}

int ezcfg_api_agent_reload(struct ezcfg_agent *agent)
{
  if (agent == NULL) {
    return -EZCFG_E_ARGUMENT ;
  }

  ezcfg_agent_reload(agent);
  return 0;
}
