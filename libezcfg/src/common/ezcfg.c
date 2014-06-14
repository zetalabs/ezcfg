/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 * ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : ezcfg.c
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2014 by ezbox-project
 *
 * History      Rev       Description
 * 2010-07-12   0.1       Write it from scratch
 * 2014-03-30   0.2       Use meta NVRAM as the raw representation
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "ezcfg.h"
#include "ezcfg-private.h"

/*
 * ezcfg - library context
 *
 * load/save the ezbox config and system environment
 * allows custom logging
 */

/*
 * ezbox config context
 */
struct ezcfg
{
  int (*log_func)(struct ezcfg *ezcfg,
                  int priority,
                  const char *file,
                  int line,
                  const char *func,
                  const char *format,
                  va_list args);
  char log_file[EZCFG_PATH_MAX];
  char *meta_nvram;
};

static int
log_stderr(struct ezcfg *ezcfg,
           int priority,
           const char *file,
           int line,
           const char *func,
           const char *format,
           va_list args)
{
  if (ezcfg->log_file[0] == '\0') {
    fprintf(stderr, "libezcfg: %s(%d)@%s: ", file, line, func);
    vfprintf(stderr, format, args);
    return EZCFG_RET_OK;
  }
  else {
    FILE *fp = fopen(ezcfg->log_file, "a");
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
 * ezcfg_common_set_log_func:
 * @ezcfg: ezcfg library context
 * @log_fn: function to be called for logging messages
 *
 * The built-in logging writes to stderr. It can be
 * overridden by a custom function, to plug log messages
 * into the users' logging functionality.
 *
 */
int
ezcfg_common_set_log_func(struct ezcfg *ezcfg,
                          int (*log_func)(struct ezcfg *ezcfg,
                                          int priority,
                                          const char *file,
                                          int line,
                                          const char *func,
                                          const char *format,
                                          va_list args))
{
  ezcfg->log_func = log_func;
  return EZCFG_RET_OK;
}

/**
 * ezcfg_new:
 *
 * Create ezcfg library context.
 *
 * Returns: a new ezcfg library context
 **/

struct ezcfg *
ezcfg_new(char *text)
{
  struct ezcfg *ezcfg = NULL;
  struct ezcfg_json *json = NULL;
  int size = 0;

  /* check text is the meta list format */
  ezcfg = malloc(sizeof(struct ezcfg));
  if (ezcfg == NULL) {
    goto fail_out;
  }

  ezcfg->log_func = log_stderr;
  ezcfg->log_file[0] = '\0';
  ezcfg->meta_nvram = NULL;

  if (text != NULL) {
    json = ezcfg_json_new(ezcfg);
    if (json == NULL) {
      goto fail_out;
    }
    if (ezcfg_json_parse_text(json, text, strlen(text)) != EZCFG_RET_OK) {
      goto fail_out;
    }
    size = ezcfg_json_get_msg_len(json);
    size += sizeof(struct nvram_header);
    ezcfg->meta_nvram = ezcfg_meta_nvram_new(size);
    if (ezcfg->meta_nvram == NULL) {
      goto fail_out;
    }
  }

  /* new ezcfg OK! */
  return ezcfg;

fail_out:
  if (json != NULL) {
    ezcfg_json_delete(json);
  }
  if (ezcfg != NULL) {
    if (ezcfg->meta_nvram != NULL) {
      ezcfg_meta_nvram_delete(ezcfg->meta_nvram);
    }
    ezcfg_delete(ezcfg);
  }
  return NULL;
}

/**
 * ezcfg_delete:
 * @ezcfg: ezcfg library context
 *
 * Release the ezcfg library context.
 *
 **/
int 
ezcfg_delete(struct ezcfg *ezcfg)
{
  ASSERT (ezcfg != NULL);
  if (ezcfg->meta_nvram != NULL) {
    ezcfg_meta_nvram_delete(ezcfg->meta_nvram);
  }
  free(ezcfg);
  return EZCFG_RET_OK;
}

int
ezcfg_log(struct ezcfg *ezcfg,
          int priority,
          const char *file,
          int line,
          const char *func,
          const char *format,
          ...)
{
  va_list args;

  va_start(args, format);
  ezcfg->log_func(ezcfg, priority, file, line, func, format, args);
  va_end(args);
  return EZCFG_RET_OK;
}

int ezcfg_common_get_log_file(struct ezcfg *ezcfg, char *buf, size_t size)
{
  if (size <= strlen(ezcfg->log_file)) {
    return EZCFG_RET_BAD;
  }
  snprintf(buf, size, "%s", ezcfg->log_file);
  return EZCFG_RET_OK;
}

int ezcfg_common_set_log_file(struct ezcfg *ezcfg, char *buf)
{
  if (strlen(buf) < sizeof(ezcfg->log_file)) {
    snprintf(ezcfg->log_file, sizeof(ezcfg->log_file), "%s", buf);
    return EZCFG_RET_OK;
  }
  return EZCFG_RET_BAD;
}

int ezcfg_common_get_log_priority(struct ezcfg *ezcfg)
{
  return LOG_ERR;
}

int ezcfg_common_get_meta_nvram(struct ezcfg *ezcfg, const char *name, char *buf, size_t len)
{
  char *value;
  int ret = EZCFG_RET_BAD;

  ASSERT(ezcfg != NULL);
  ASSERT(name != NULL);
  ASSERT(buf != NULL);
  ASSERT(len > 0);

  if (ezcfg->meta_nvram == NULL) {
    return ret;
  }

  ret = ezcfg_meta_nvram_get_entry_value(ezcfg->meta_nvram, name, &value);
  if (ret != EZCFG_RET_OK) {
    return ret;
  }

  if (strlen(value) < len) {
    snprintf(buf, len, "%s", value);
    ret = EZCFG_RET_OK;
  }
  else {
    ret = EZCFG_RET_BAD;
  }

  free(value);
  return ret;
}
