/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 * ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : ezcfg-nvram_agent.h
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2015 by ezbox-project
 *
 * History      Rev       Description
 * 2015-12-20   0.1       Prepare for new NVRAM model
 * ============================================================================
 */

#ifndef _EZCFG_NVRAM_AGENT_H_
#define _EZCFG_NVRAM_AGENT_H_

/* ezcfg agent nvram name prefix */
#define EZCFG_NVRAM_PREFIX_AGENT                 "agent."

/* ezcfg agent nvram names */
#define EZCFG_NVRAM_AGENT_NAME                   "name"
#define EZCFG_NVRAM_AGENT_NAMESPACE              "namespace"
#define EZCFG_NVRAM_AGENT_PROCESS_NAMESPACE \
	"process_namespace"
#define EZCFG_NVRAM_AGENT_MASTER_THREAD_NAMESPACE \
	"master_thread_namespace"
#define EZCFG_NVRAM_AGENT_WORKER_THREAD_NAMESPACE \
	"worker_thread_namespace"
#define EZCFG_NVRAM_AGENT_SOCKET_QUEUE_LENGTH \
	"socket_queue_length"
#define EZCFG_NVRAM_AGENT_WORKER_THREADS_MAX \
	"worker_threads_max"
#define EZCFG_NVRAM_AGENT_SOCKET_NAMESPACE \
	"socket_namespace"
#define EZCFG_NVRAM_AGENT_CHILD_PROCESS_NAMESPACE \
	"child_process_namespace"
#define EZCFG_NVRAM_AGENT_ENVIRONMENT_NAMESPACE \
	"environment_namespace"

#endif
