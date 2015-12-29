/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* ============================================================================
 * Project Name : ezbox configuration utilities
 * Module Name  : util/util_socket_protocol.c
 *
 * Description  : socket protocol settings
 *
 * Copyright (C) 2008-2016 by ezbox-project
 *
 * History      Rev       Description
 * 2015-12-27   0.1       Write it from scrach
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

#include "ezcfg.h"
#include "ezcfg-private.h"

struct role_pair {
  int index;
  char *name;
};

static struct role_pair ezcfg_support_socket_roles[] = {
  { EZCFG_SOCKET_ROLE_UNKNOWN, NULL },
  { EZCFG_SOCKET_ROLE_SERVER, EZCFG_SOCKET_ROLE_SERVER_STRING },
  { EZCFG_SOCKET_ROLE_CLIENT, EZCFG_SOCKET_ROLE_CLIENT_STRING },
};

int ezcfg_util_socket_role_get_index(char *name)
{
  size_t i;
  struct role_pair *pip;
  for (i = 1; i < ARRAY_SIZE(ezcfg_support_socket_roles); i++) {
    pip = &(ezcfg_support_socket_roles[i]);
    if (strcmp(pip->name, name) == 0)
      return pip->index;
  }
  return EZCFG_SOCKET_ROLE_UNKNOWN;
}

bool ezcfg_util_socket_is_supported_role(const int role)
{
  size_t i;
  struct role_pair *pip;
  for (i = 1; i < ARRAY_SIZE(ezcfg_support_socket_roles); i++) {
    pip = &(ezcfg_support_socket_roles[i]);
    if (role == pip->index)
      return true;
  }
  return false;
}

