/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 * ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : ezcfg-nvram_environment.h
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2016 by ezbox-project
 *
 * History      Rev       Description
 * 2015-12-28   0.1       Prepare for new NVRAM model
 * ============================================================================
 */

#ifndef _EZCFG_NVRAM_ENVIRONMENT_H_
#define _EZCFG_NVRAM_ENVIRONMENT_H_

/* ezcfg environment nvram name prefix */
#define EZCFG_NVRAM_PREFIX_ENVIRONMENT                 "environment."

/* ezcfg environment nvram names */
#define EZCFG_NVRAM_ENVIRONMENT_NAME                   "name"
#define EZCFG_NVRAM_ENVIRONMENT_THREAD_NAMESPACE \
	"thread_namespace"
#define EZCFG_NVRAM_ENVIRONMENT_SOCKET_NAMESPACE \
	"socket_namespace"

#endif
