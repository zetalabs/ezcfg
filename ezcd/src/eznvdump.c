/* ============================================================================
 * Project Name : ezbox Configuration Daemon
 * Module Name  : eznvdump.c
 *
 * Description  : ezbox config NVRAM dump utils
 *
 * Copyright (C) 2008-2016 by ezbox-project
 *
 * History      Rev       Description
 * 2016-12-03   0.1       Write it from scratch
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
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>
#include <ctype.h>
#include <stdarg.h>

#include "ezcd.h"

#if 1
static bool debug = true;
#ifdef ANDROID_BUILD
#define DBG(format, args...)                      \
  do {                                            \
    FILE *dbg_fp;                                 \
    if (debug == true)                            \
      dbg_fp = fopen("/data/eznvdump.log", "a");     \
    else                                          \
      dbg_fp = fopen("/dev/kmsg", "a");           \
    if (dbg_fp) {                                 \
      fprintf(dbg_fp, format, ## args);           \
      fclose(dbg_fp);                             \
    }                                             \
  } while(0)
#else
#define DBG(format, args...)                      \
  do {                                            \
    FILE *dbg_fp;                                 \
    if (debug == true)                            \
      dbg_fp = fopen("/tmp/eznvdump.log", "a");      \
    else                                          \
      dbg_fp = fopen("/dev/kmsg", "a");           \
    if (dbg_fp) {                                 \
      fprintf(dbg_fp, format, ## args);           \
      fclose(dbg_fp);                             \
    }                                             \
  } while(0)
#endif
#else
#define DBG(format, args...)
#endif

static void eznvdump_show_usage(void)
{
  printf("Usage: eznvdump [-q] [-c config file]\n");
  printf("             [-j \"NVRAM JSON representation\"]\n");
  printf("             [-f NVRAM JSON representation file]\n");
  printf("             [-n namespace]\n");
  printf("\n");
  printf("  [-q]--\n");
  printf("    run in quiet mode\n");
  printf("  [-c]--\n");
  printf("    config file, default : \"%s\n", EZNVDUMP_CONFIG_FILE_PATH);
  printf("  [-j]--\n");
  printf("    NVRAM JSON representation, ex: \"{\"name\":\"value\"}\"\n");
  printf("  [-f]--\n");
  printf("    NVRAM JSON representation file\n");
  printf("  [-n]--\n");
  printf("    namespace\n");
  printf("\n");
}

int eznvdump_main(int argc, char **argv)
{
  int opt = 0;
  int rc = 0;
  bool quiet_mode = false;
  char *ns = NULL;
  char *conf_file = EZNVC_CONFIG_FILE_PATH;
  char *init_conf = NULL;
  char *result = NULL;
  size_t init_conf_len = 0;

  DBG("%s(%d) entered!\n", __func__, __LINE__);

  while ((opt = getopt(argc, argv, "qc:n:")) != -1) {
    switch (opt) {
    case 'q':
      quiet_mode = true;
      break;
    case 'c':
      conf_file = optarg;
      break;
    case 'n':
      ns = optarg;
      break;
    default: /* '?' */
      eznvdump_show_usage();
      rc = -EZCFG_E_ARGUMENT;
      goto func_out;
    }
  }

  if (conf_file == NULL) {
    printf("config file does not set!\n");
    rc = -EZCFG_E_ARGUMENT;
    goto func_out;
  }

  if (EZCFG_RET_OK != utils_file_get_content(conf_file, &init_conf, &init_conf_len)) {
    printf("can't get file [%s] content.\n", conf_file);
    rc = -EZCFG_E_ARGUMENT;
    goto func_out;
  }

  rc = ezcfg_api_nvram_dump(init_conf, ns, &result);
  if (quiet_mode == false) {
    if (rc < 0) {
      printf("ERROR\n");
    }
    else {
      printf("OK\n");
    }
  }
func_out:
  if (init_conf)
    free(init_conf);

  if (result)
    free(result);

  return rc;
}
