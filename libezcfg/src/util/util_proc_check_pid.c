/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* ============================================================================
 * Project Name : ezbox configuration utilities
 * Module Name  : util/util_proc_check_pid.c
 *
 * Description  : execute command without shell, replace system() call
 *
 * Copyright (C) 2008-2016 by ezbox-project
 *
 * History      Rev       Description
 * 2015-12-25   0.1       Write it from scrach
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
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <dirent.h>

#include "ezcfg.h"
#include "ezcfg-private.h"

#if 0
#define DBG(format, args...) do { \
  char path[256]; \
  FILE *fp; \
  snprintf(path, 256, "/tmp/%d-debug.txt", getpid()); \
  fp = fopen(path, "a"); \
  if (fp) { \
    fprintf(fp, format, ## args); \
    fclose(fp); \
  } \
} while(0)
#else
#define DBG(format, args...)
#endif

int ezcfg_util_proc_check_no_pid(pid_t pid)
{
  pid_t my_pid = -1;
  DIR *dir;
  struct dirent *next;
  if ((dir = opendir("/proc")) == NULL) {
    perror("Cannot open /proc");
    return EZCFG_RET_FAIL;
  }

  while ((next = readdir(dir)) != NULL) {
    /* If it isn't a number, we don't want it */
    if (!isdigit(*next->d_name))
      continue;
    my_pid = strtol(next->d_name, NULL, 0);
    if (pid == my_pid) {
      closedir(dir);
      return EZCFG_RET_FAIL;
    }
  }
  closedir(dir);
  return EZCFG_RET_OK;
}

int ezcfg_util_proc_check_pid(pid_t pid)
{
  pid_t my_pid = -1;
  DIR *dir;
  struct dirent *next;
  if ((dir = opendir("/proc")) == NULL) {
    perror("Cannot open /proc");
    return EZCFG_RET_FAIL;
  }

  while ((next = readdir(dir)) != NULL) {
    /* If it isn't a number, we don't want it */
    if (!isdigit(*next->d_name))
      continue;
    my_pid = strtol(next->d_name, NULL, 0);
    if (pid == my_pid) {
      closedir(dir);
      return EZCFG_RET_OK;
    }
  }
  closedir(dir);
  return EZCFG_RET_FAIL;
}

