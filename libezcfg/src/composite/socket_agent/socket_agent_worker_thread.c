/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 * ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : composite/socket_agent/socket_agent_worker_thread.c
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2016 by ezbox-project
 *
 * History      Rev       Description
 * 2015-12-29   0.1       Modify it from agent/agent_worker.c
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
#include <pthread.h>

#include "ezcfg.h"
#include "ezcfg-private.h"

#include "socket_agent_local.h"

/*
 * private functions
 */
static int worker_thread_get_socket_from_queue(struct worker_thread_arg *arg, int wait_time)
{
  struct timespec ts;
  struct ezcfg_socket_agent *agent = NULL;

  ASSERT(arg != NULL);
  ASSERT(wait_time >= 0);

  agent = arg->agent;

  pthread_mutex_lock(&(agent->mw_thread_mutex));
  /* If the queue is empty, wait. We're idle at this point. */
  agent->num_idle_worker_threads++;
  while (agent->mw_sq_head == agent->mw_sq_tail) {
    ts.tv_nsec = 0;
    ts.tv_sec = time(NULL) + wait_time;
    if (pthread_cond_timedwait(&(agent->mw_sq_empty_cond), &(agent->mw_thread_mutex), &ts) != 0) {
      /* Timeout! release the mutex and return */
      pthread_mutex_unlock(&(agent->mw_thread_mutex));
      return EZCFG_RET_FAIL;
    }
  }
  ASSERT(agent->mw_sq_head > agent->mw_sq_tail);

  /* We're going busy now: got a socket to process! */
  agent->num_idle_worker_threads--;

  /* Copy socket from the queue and increment tail */
  ezcfg_socket_queue_get_socket(agent->mw_socket_queue, agent->mw_sq_tail % agent->mw_sq_len, arg->sp);
  agent->mw_sq_tail++;

  /* Wrap pointers if needed */
  while (agent->mw_sq_tail >= agent->mw_sq_len) {
    agent->mw_sq_tail -= agent->mw_sq_len;
    agent->mw_sq_head -= agent->mw_sq_len;
  }
  pthread_cond_signal(&(agent->mw_sq_full_cond));
  pthread_mutex_unlock(&(agent->mw_thread_mutex));

  return EZCFG_RET_OK;
}

static void worker_thread_reset_connection_attributes(struct worker_thread_arg *arg) {
  struct ezcfg_socket_agent *agent = NULL;
  struct ezcfg *ezcfg = NULL;

  ASSERT(arg != NULL);
  ASSERT(arg->agent != NULL);
  agent = arg->agent;
  ezcfg = agent->ezcfg;

  switch(arg->proto) {
  case EZCFG_PROTO_NV_JSON_HTTP :
    ezcfg_nv_json_http_reset_attributes(arg->proto_data);
    break;
  default :
    err(ezcfg, "unknown protocol\n");
  }

  arg->num_bytes_sent = 0;
}

static void worker_thread_close_connection(struct worker_thread_arg *arg)
{
  ASSERT(arg != NULL);

  ezcfg_socket_close_sock(arg->sp);
}

static void worker_thread_init_protocol_data(struct worker_thread_arg *arg)
{
  struct ezcfg_socket_agent *agent = NULL;
  struct ezcfg *ezcfg = NULL;

  ASSERT(arg != NULL);
  /* proto_data should be empty before init */
  ASSERT(arg->proto_data == NULL);
  /* socket should not be empty before init */
  ASSERT(arg->sp != NULL);

  ASSERT(arg->agent != NULL);
  agent = arg->agent;
  ezcfg = agent->ezcfg;

  /* set communication protocol */
  arg->proto = ezcfg_socket_get_proto(arg->sp);
  EZDBG("%s(%d) arg->proto=%d\n", __func__, __LINE__, arg->proto);

  /* initialize protocol data structure */
  switch(arg->proto) {
  case EZCFG_PROTO_NV_JSON_HTTP :
    EZDBG("%s(%d) EZCFG_PROTO_NV_JSON_HTTP\n", __func__, __LINE__);
    arg->proto_data = ezcfg_nv_json_http_new(ezcfg);
    break;
  default :
    EZDBG("%s(%d) unknown protocol\n", __func__, __LINE__);
    info(ezcfg, "unknown protocol\n");
  }
}

static void worker_thread_process_new_connection(struct worker_thread_arg *arg)
{
  struct ezcfg_socket_agent *agent = NULL;
  struct ezcfg *ezcfg = NULL;

  ASSERT(arg != NULL);
  ASSERT(arg->agent != NULL);
  agent = arg->agent;
  ezcfg = agent->ezcfg;

  EZDBG("%s(%d)\n", __func__, __LINE__);
  worker_thread_reset_connection_attributes(arg);

  /* dispatch protocol handler */
  switch(arg->proto) {
  case EZCFG_PROTO_NV_JSON_HTTP :
    EZDBG("%s(%d) EZCFG_PROTO_NV_JSON_HTTP\n", __func__, __LINE__);
    local_socket_agent_worker_thread_process_nv_json_http_new_connection(arg);
    break;
  default :
    EZDBG("%s(%d) unknown protocol\n", __func__, __LINE__);
    err(ezcfg, "unknown protocol\n");
  }
}

static void worker_thread_release_protocol_data(struct worker_thread_arg *arg)
{
  struct ezcfg_socket_agent *agent = NULL;
  struct ezcfg *ezcfg = NULL;

  ASSERT(arg != NULL);

  ASSERT(arg->agent != NULL);
  agent = arg->agent;
  ezcfg = agent->ezcfg;

  /* release protocol data */
  switch(arg->proto) {
  case EZCFG_PROTO_NV_JSON_HTTP :
    ezcfg_nv_json_http_del(arg->proto_data);
    arg->proto_data = NULL;
    break;
  default :
    err(ezcfg, "unknown protocol\n");
  }
}


/*
 * local public functions
 */
int local_socket_agent_worker_thread_printf(struct worker_thread_arg *arg, const char *fmt, ...)
{
  char *buf;
  int buf_len;
  int len;
  int ret;
  va_list ap;

  buf_len = EZCFG_BUFFER_SIZE ;
  buf = (char *)malloc(buf_len);
  if (buf == NULL) {
    return -1;
  }

  va_start(ap, fmt);
  len = vsnprintf(buf, buf_len, fmt, ap);
  va_end(ap);

  ret = ezcfg_socket_write(arg->sp, buf, len, 0);
  free(buf);
  return ret;
}

int local_socket_agent_worker_thread_write(struct worker_thread_arg *arg, const char *buf, int len)
{
  return ezcfg_socket_write(arg->sp, buf, len, 0);
}


/*
 * worker thread routine
 */
void *local_socket_agent_worker_thread_routine(void *arg)
{
  struct worker_thread_arg *worker_thread_arg = NULL;
  struct ezcfg_socket_agent *agent = NULL;
  struct ezcfg_thread *master_thread = NULL;
  struct ezcfg_thread *worker_thread = NULL;
  int ret = EZCFG_RET_FAIL;

  ASSERT(arg != NULL);
  worker_thread_arg = (struct worker_thread_arg *)arg;

  ASSERT(worker_thread_arg->agent != NULL);
  ASSERT(worker_thread_arg->sp != NULL);
  ASSERT(worker_thread_arg->worker_thread != NULL);
  agent = worker_thread_arg->agent;
  worker_thread = worker_thread_arg->worker_thread;

  ASSERT(agent->master_thread != NULL);
  master_thread = agent->master_thread;

  EZDBG("%s(%d)\n", __func__, __LINE__);
  while ((ezcfg_thread_state_is_running(master_thread) == EZCFG_RET_OK) &&
         (worker_thread_get_socket_from_queue(worker_thread_arg, EZCFG_AGENT_WORKER_WAIT_TIME) == EZCFG_RET_OK)) {

    EZDBG("%s(%d)\n", __func__, __LINE__);
    /* record start working time */
    worker_thread_arg->birth_time = time(NULL);

    EZDBG("%s(%d)\n", __func__, __LINE__);
    /* initialize protocol data */
    worker_thread_init_protocol_data(worker_thread_arg);

    EZDBG("%s(%d)\n", __func__, __LINE__);
    /* process the connection */
    if (worker_thread_arg->proto_data != NULL) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      worker_thread_process_new_connection(worker_thread_arg);
    }

    EZDBG("%s(%d)\n", __func__, __LINE__);
    /* close connection */
    worker_thread_close_connection(worker_thread_arg);

    EZDBG("%s(%d)\n", __func__, __LINE__);
    /* release protocol data */
    if (worker_thread_arg->proto_data != NULL) {
      worker_thread_release_protocol_data(worker_thread_arg);
    }
  }

  /* clean up data in master thread */
  pthread_mutex_lock(&(agent->mw_thread_mutex));

  EZDBG("%s(%d)\n", __func__, __LINE__);
  ezcfg_thread_stop(worker_thread);
  EZDBG("%s(%d)\n", __func__, __LINE__);
  ret = ezcfg_linked_list_remove(agent->worker_thread_list, worker_thread);
  EZDBG("%s(%d)\n", __func__, __LINE__);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d) remove worker_thread error\n", __func__, __LINE__);
  }
  agent->num_worker_threads--;
  EZDBG("%s(%d)\n", __func__, __LINE__);
  pthread_cond_signal(&(agent->mw_thread_sync_cond));
  EZDBG("%s(%d)\n", __func__, __LINE__);

  pthread_mutex_unlock(&(agent->mw_thread_mutex));

  EZDBG("%s(%d) exit\n", __func__, __LINE__);
  //return arg;
  return NULL;
}

/*
 * Don't clear agent and worker_thread, since they are from agent struct.
 */
int local_socket_agent_worker_thread_arg_del(void *arg)
{
  struct worker_thread_arg *worker_thread_arg = arg;

  EZDBG("%s(%d)\n", __func__, __LINE__);
  if (worker_thread_arg->sp) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    ezcfg_socket_del(worker_thread_arg->sp);
    EZDBG("%s(%d)\n", __func__, __LINE__);
    worker_thread_arg->sp = NULL;
  }
  EZDBG("%s(%d)\n", __func__, __LINE__);
  if (worker_thread_arg->proto_data) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    worker_thread_release_protocol_data(worker_thread_arg);
    EZDBG("%s(%d)\n", __func__, __LINE__);
    worker_thread_arg->proto_data = NULL;
  }
  EZDBG("%s(%d)\n", __func__, __LINE__);

  return EZCFG_RET_OK;
}

/*
 * stop worker thread
 */
int local_socket_agent_worker_thread_stop(void *arg)
{
  //struct worker_thread_arg *worker_thread_arg = arg;

  EZDBG("%s(%d)\n", __func__, __LINE__);
  return EZCFG_RET_OK;
}
