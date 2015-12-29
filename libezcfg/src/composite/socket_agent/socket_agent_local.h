/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 *  ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : composite/socket_agent/socket_agent_local.h
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2014 by ezbox-project
 *
 * History      Rev       Description
 * 2015-12-29   0.1       Split it from composite/socket_agent/socket_agent.c
 * ============================================================================
 */

#ifndef _EZCFG_LOCAL_COMPOSITE_SOCKET_AGENT_SOCKET_AGENT_LOCAL_H_
#define _EZCFG_LOCAL_COMPOSITE_SOCKET_AGENT_SOCKET_AGENT_LOCAL_H_

#include "ezcfg-types.h"

/* bitmap for agent state */
#define AGENT_STATE_STOPPED     0
#define AGENT_STATE_RUNNING     1
#define AGENT_STATE_STOPPING    2

/*
 * ezcfg_socket_agent:
 *
 * Opaque object handling one event source.
 * Multi-Agents System model - agent part.
 */
struct ezcfg_socket_agent {
  struct ezcfg *ezcfg; /* agent core */
  int state; /* Should we stop event loop */

  sigset_t *sigset;
  int mutex_init; /* mutex|lock init flag */

  /* for child process model */
  struct ezcfg_process *process;
  struct ezcfg_linked_list *child_process_list;

  pthread_mutex_t process_mutex; /* Protects child_process_list */
  /* end of child process model */

  /* for master/worker multi-threads model */
  struct ezcfg_thread *master_thread;
  struct ezcfg_linked_list *worker_thread_list;

  int master_thread_stop; /* master thread stop flag */
  int worker_threads_max; /* MAX number of worker threads */
  int num_worker_threads; /* Number of worker threads */
  int num_idle_worker_threads; /* Number of idle worker threads */

  pthread_mutex_t mw_thread_mutex; /* Protects master/worker (max|num)_threads */
  pthread_rwlock_t mw_thread_rwlock; /* Protects options, callbacks */
  pthread_cond_t mw_thread_sync_cond; /* Condvar for master/worker thread sync */

  struct ezcfg_socket *mw_listening_sockets;
  pthread_mutex_t mw_ls_mutex; /* Protects mw_listening_sockets */

  struct ezcfg_socket *mw_socket_queue; /* Accepted sockets */
  int mw_sq_len; /* Length of the socket queue */
  int mw_sq_head; /* Head of the socket queue */
  int mw_sq_tail; /* Tail of the socket queue */
  pthread_cond_t mw_sq_empty_cond; /* Socket queue empty condvar */
  pthread_cond_t mw_sq_full_cond;  /* Socket queue full condvar */
  /* end of master/worker multi-threads model */

  /* for environment thread part */
  struct ezcfg_thread *env_thread;
  struct ezcfg_socket *env_sp;
  struct ezcfg_linked_list *sub_agent_thread_list;

  int env_thread_stop; /* environment thread stop flag */

  pthread_mutex_t env_thread_mutex; /* Protects environment threads */
  pthread_mutex_t sub_agent_thread_list_mutex; /* Protects sub_agent_thread_list */
  /* end of environment thread part */
};

struct worker_thread_arg {
  struct ezcfg_socket_agent *agent;
  struct ezcfg_thread *worker_thread;
  struct ezcfg_socket *sp;
  int proto;
  void *proto_data;
  time_t birth_time;
  int64_t num_bytes_sent;
};

#endif /* _EZCFG_LOCAL_COMPOSITE_SOCKET_AGENT_SOCKET_AGENT_LOCAL_H_ */
