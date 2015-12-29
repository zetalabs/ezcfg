/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 *  ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : composite/socket_agent/socket_agent.c
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2016 by ezbox-project
 *
 * History      Rev       Description
 * 2013-07-29   0.1       Write it from scratch
 * 2015-06-14   0.2       Reimplement it by using process/thread objects
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
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/un.h>
#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>

#include "ezcfg.h"
#include "ezcfg-private.h"

#include "socket_agent_local.h"

#ifndef PR_SET_CHILD_SUBREAPER
#define PR_SET_CHILD_SUBREAPER 36
#endif

/* Private variables */
static int child_process_changed = 0; /* flag for receiving SIGCHLD */
static int terminate_process = 0; /* flag for receiving SIGTERM */

/* Private functions */
/*
 * only delete agent_new() allocated resources before pthread_mutex initialized
 * other resources should be deleted in agent_finish()
 */
static int agent_clr(struct ezcfg_socket_agent *agent)
{
  int ret = EZCFG_RET_FAIL;

  if (agent->child_process_list) {
    ret = ezcfg_linked_list_del(agent->child_process_list);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d) delete child_process_list error!\n", __func__, __LINE__);
    }
    agent->child_process_list = NULL;
  }

  if (agent->worker_thread_list) {
    ret = ezcfg_linked_list_del(agent->worker_thread_list);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d) delete worker_thread_list error!\n", __func__, __LINE__);
    }
    agent->worker_thread_list = NULL;
  }

  if (agent->sub_agent_thread_list) {
    ret = ezcfg_linked_list_del(agent->sub_agent_thread_list);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d) delete sub_agent_thread_list error!\n", __func__, __LINE__);
    }
    agent->sub_agent_thread_list = NULL;
  }

  if (agent->env_thread) {
    ret = ezcfg_thread_del(agent->env_thread);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d) delete env_thread error!\n", __func__, __LINE__);
    }
    agent->env_thread = NULL;
  }

  if (agent->env_sp) {
    ret = ezcfg_socket_del(agent->env_sp);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d) delete env_sp error!\n", __func__, __LINE__);
    }
    agent->env_sp = NULL;
  }

  if (agent->master_thread) {
    ret = ezcfg_thread_del(agent->master_thread);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d) delete master_thread error!\n", __func__, __LINE__);
    }
    agent->master_thread = NULL;
  }

  if (agent->process) {
    ezcfg_process_del(agent->process);
    agent->process = NULL;
  }

  if (agent->mutex_init) {
    pthread_cond_destroy(&(agent->mw_sq_empty_cond));
    pthread_cond_destroy(&(agent->mw_sq_full_cond));

    pthread_mutex_destroy(&(agent->mw_ls_mutex));

    pthread_cond_destroy(&(agent->mw_thread_sync_cond));
    pthread_rwlock_destroy(&(agent->mw_thread_rwlock));
    pthread_mutex_destroy(&(agent->mw_thread_mutex));
    pthread_mutex_destroy(&(agent->process_mutex));

    pthread_mutex_destroy(&(agent->env_thread_mutex));
    pthread_mutex_destroy(&(agent->sub_agent_thread_list_mutex));
  }

  return EZCFG_RET_OK;
}

static int worker_thread_get_socket_from_queue(struct ezcfg_socket_agent *agent, struct ezcfg_socket *sp, int wait_time)
{
  struct timespec ts;

  ASSERT(agent != NULL);
  ASSERT(sp != NULL);
  ASSERT(wait_time >= 0);

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
  ezcfg_socket_queue_get_socket(agent->mw_socket_queue, agent->mw_sq_tail % agent->mw_sq_len, sp);
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

  /* initialize protocol data structure */
  switch(arg->proto) {
  case EZCFG_PROTO_NV_JSON_HTTP :
    arg->proto_data = ezcfg_nv_json_http_new(ezcfg);
    break;
  default :
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

  worker_thread_reset_connection_attributes(arg);

  /* dispatch protocol handler */
  switch(arg->proto) {
  case EZCFG_PROTO_NV_JSON_HTTP :
    //ezcfg_socket_agent_worker_thread_process_nv_json_http_new_connection(arg);
    break;
  default :
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
 * worker thread routine
 */
static void *worker_thread_routine(void *arg)
{
  struct worker_thread_arg *worker_thread_arg = NULL;
  struct ezcfg_socket_agent *agent = NULL;

  ASSERT(arg != NULL);
  worker_thread_arg = (struct worker_thread_arg *)arg;

  ASSERT(worker_thread_arg->agent != NULL);
  agent = worker_thread_arg->agent;

  while ((ezcfg_thread_state_is_running(agent->master_thread) == EZCFG_RET_OK) &&
         (worker_thread_get_socket_from_queue(agent, worker_thread_arg->sp, EZCFG_AGENT_WORKER_WAIT_TIME) == EZCFG_RET_OK)) {

    /* record start working time */
    worker_thread_arg->birth_time = time(NULL);

    /* initialize protocol data */
    worker_thread_init_protocol_data(worker_thread_arg);

    /* process the connection */
    if (worker_thread_arg->proto_data != NULL) {
      worker_thread_process_new_connection(worker_thread_arg);
    }

    /* close connection */
    worker_thread_close_connection(worker_thread_arg);

    /* release protocol data */
    if (worker_thread_arg->proto_data != NULL) {
      worker_thread_release_protocol_data(worker_thread_arg);
    }
  }

  return arg;
}

/*
 * Don't clear agent and worker_thread, since they are from agent struct.
 */
static int worker_thread_arg_del(void *arg)
{
  struct worker_thread_arg *worker_thread_arg = arg;

  if (worker_thread_arg->sp) {
    ezcfg_socket_del(worker_thread_arg->sp);
    worker_thread_arg->sp = NULL;
  }
  if (worker_thread_arg->proto_data) {
    worker_thread_release_protocol_data(worker_thread_arg);
    worker_thread_arg->proto_data = NULL;
  }

  return EZCFG_RET_OK;
}

/*
 * stop worker thread
 */
static int worker_thread_stop(void *arg)
{
  //struct worker_thread_arg *worker_thread_arg = arg;

  EZDBG("%s(%d)\n", __func__, __LINE__);
  return EZCFG_RET_OK;
}

static void add_to_set(int fd, fd_set *set, int *max_fd)
{
  FD_SET(fd, set);
  if (fd > *max_fd) {
    *max_fd = (int) fd;
  }
}

/* Master thread adds accepted socket to a queue */
static int put_socket(struct ezcfg_socket_agent *agent, const struct ezcfg_socket *sp)
{
  struct ezcfg *ezcfg = NULL;
  int ret = EZCFG_RET_FAIL;
  char *val = NULL;
  struct ezcfg_thread *worker_thread = NULL;
  struct worker_thread_arg *worker_thread_arg = NULL;

  ASSERT(agent != NULL);
  ASSERT(sp != NULL);

  ezcfg = agent->ezcfg;

  pthread_mutex_lock(&(agent->mw_thread_mutex));

  /* If the queue is full, wait */
  while (agent->mw_sq_head - agent->mw_sq_tail >= agent->mw_sq_len) {
    pthread_cond_wait(&(agent->mw_sq_full_cond), &(agent->mw_thread_mutex));
  }
  ASSERT(agent->mw_sq_head - agent->mw_sq_tail < agent->mw_sq_len);

  /* Copy socket to the queue and increment head */
  ezcfg_socket_queue_set_socket(agent->mw_socket_queue, agent->mw_sq_head % agent->mw_sq_len, sp);
  agent->mw_sq_head++;

  /* If there is no idle thread, start one */
  if ((agent->num_idle_worker_threads == 0) &&
      (agent->num_worker_threads < agent->worker_threads_max)) {
    /* There must be an agent act executor link with core state*/
    EZDBG("%s(%d)\n", __func__, __LINE__);
    ret = ezcfg_common_get_nvram_entry_value(ezcfg, NVRAM_NAME(AGENT, WORKER_THREAD_NAMESPACE), &val);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      goto func_out;
    }
    if (val) {
      worker_thread = ezcfg_thread_new(ezcfg, val);
      free(val);
      val = NULL;
    }
    if (worker_thread == NULL) {
      err(ezcfg, "Cannot prepare worker thread: %m\n");
      goto func_out;
    }

    /* Set the worker thread start routine */
    ret = ezcfg_thread_set_start_routine(worker_thread, worker_thread_routine, worker_thread_arg);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      err(ezcfg, "can not set worker thread start routine");
      goto func_out;
    }
    /* worker_thread_arg has been put to worker_thread */
    worker_thread_arg = NULL;

    /*
     * Since agent has been passed to worker_thread_routine(),
     * we don't want it been freed when worker thread stopped.
     * Here we set an dummy arg delete function to worker thread
     */
    ret = ezcfg_thread_set_arg_del_handler(worker_thread, worker_thread_arg_del);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      err(ezcfg, "can not set worker thread arg delete function");
      goto func_out;
    }

    ret = ezcfg_thread_set_stop(worker_thread, worker_thread_stop);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      err(ezcfg, "can not set worker thread stop function");
      goto func_out;
    }

    ret = ezcfg_thread_start(worker_thread);
    if (ret != EZCFG_RET_OK) {
      err(ezcfg, "Cannot start thread: %m\n");
      goto func_out;
    }
    /* add to worker list */
    ret = ezcfg_linked_list_append(agent->worker_thread_list, worker_thread);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      ezcfg_thread_stop(worker_thread);
      goto func_out;
    }
    /* worker_thread has been appened to agent->worker_thread_list */
    worker_thread = NULL;
    agent->num_worker_threads++;
  }
  ret = EZCFG_RET_OK;

func_out:
  if (worker_thread_arg) {
    worker_thread_arg_del(worker_thread_arg);
    worker_thread_arg = NULL;
  }
  if (worker_thread) {
    ezcfg_thread_del(worker_thread);
    worker_thread = NULL;
  }
  pthread_cond_signal(&(agent->mw_sq_empty_cond));
  pthread_mutex_unlock(&(agent->mw_thread_mutex));
  return ret;
}

static int accept_new_connection(struct ezcfg_socket_agent *agent,
                                  struct ezcfg_socket *listener)
{
  struct ezcfg *ezcfg = NULL;
  struct ezcfg_socket *accepted = NULL;
  bool allowed = false;
  int ret = EZCFG_RET_FAIL;

  ASSERT(agent != NULL);
  ASSERT(listener != NULL);

  ezcfg = agent->ezcfg;

  accepted = ezcfg_socket_new_accepted_socket(listener);
  if (accepted == NULL) {
    err(ezcfg, "new accepted socket fail.\n");
    return false;
  }

  allowed = true;

  if (allowed == true) {
    ret = put_socket(agent, accepted);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d) put_socket() accepted socket error.\n", __func__, __LINE__);
      err(ezcfg, "put_socket() accepted socket error.\n");
    }
    /*FIXME: don't ezcfg_socket_del(), it has been copy to queue */
    free(accepted);
  }
  else {
    ezcfg_socket_del(accepted);
    ret = EZCFG_RET_OK;
  }

  return ret;
}

/*
 * Deallocate ezcfg master context, free up the resources
 * when master_new() success, this function will be called before master_del()
 */
static void master_thread_finish(struct ezcfg_socket_agent *agent)
{
  //struct ezcfg_thread *worker_thread;

  pthread_mutex_lock(&(agent->mw_thread_mutex));

  /* Close all listening sockets */
  pthread_mutex_lock(&(agent->mw_ls_mutex));
  if (agent->mw_listening_sockets != NULL) {
    ezcfg_socket_list_delete(&(agent->mw_listening_sockets));
    agent->mw_listening_sockets = NULL;
  }
  pthread_mutex_unlock(&(agent->mw_ls_mutex));

  /* Close all workers' socket */
#if 0
  worker_thread = agent->worker_thread_list;
  while (worker != NULL) {
    ezcfg_worker_close_connection(worker);
    worker = ezcfg_worker_get_next(worker);
  }
#endif

  /* Wait until all threads finish */
  while (agent->num_worker_threads > 0) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    pthread_cond_wait(&(agent->mw_thread_sync_cond), &(agent->mw_thread_mutex));
  }
  agent->worker_threads_max = 0;

  pthread_mutex_unlock(&(agent->mw_thread_mutex));

  /* signal master_thread_stop() that we have done */
  agent->master_thread_stop = 1;
}

static void *master_thread_routine(void *arg)
{
  struct ezcfg_socket_agent *agent = NULL;
  fd_set read_set;
  struct ezcfg *ezcfg;
  struct ezcfg_socket *sp;
  struct timeval tv;
  int max_fd;
  int retval;

  ASSERT(arg != NULL);

  agent = (struct ezcfg_socket_agent *)arg;
  ezcfg = agent->ezcfg;

  while (ezcfg_thread_state_is_running(agent->master_thread) == EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    FD_ZERO(&read_set);
    max_fd = -1;

    /* Add listening sockets to the read set */
    /* lock mutex before handling mw_listening_sockets */
    pthread_mutex_lock(&(agent->mw_ls_mutex));

    for (sp = agent->mw_listening_sockets; sp != NULL; sp = ezcfg_socket_list_next(&sp)) {
      add_to_set(ezcfg_socket_get_sock(sp), &read_set, &max_fd);
    }

    /* unlock mutex after handling mw_listening_sockets */
    pthread_mutex_unlock(&(agent->mw_ls_mutex));

    /* wait up to EZCFG_AGENT_MASTER_WAIT_TIME seconds. */
    tv.tv_sec = EZCFG_AGENT_MASTER_WAIT_TIME;
    tv.tv_usec = 0;

    retval = select(max_fd + 1, &read_set, NULL, NULL, &tv);
    if (retval == -1) {
      perror("select()");
      err(ezcfg, "select() %m\n");
    }
    else if (retval == 0) {
      /* no data arrived, do nothing */
      do {} while(0);
    }
    else {
      /* lock mutex before handling mw_listening_sockets */
      pthread_mutex_lock(&(agent->mw_ls_mutex));

      for (sp = agent->mw_listening_sockets;
           sp != NULL;
           sp = ezcfg_socket_list_next(&sp)) {
        if (FD_ISSET(ezcfg_socket_get_sock(sp), &read_set)) {
          if (accept_new_connection(agent, sp) != EZCFG_RET_OK) {
            /* re-enable the socket */
            err(ezcfg, "accept_new_connection() failed\n");

            if (ezcfg_socket_enable_again(sp) < 0) {
              err(ezcfg, "ezcfg_socket_enable_again() failed\n");
              ezcfg_socket_list_delete_socket(&(agent->mw_listening_sockets), sp);
            }
          }
        }
      }

      /* unlock mutex after handling mw_listening_sockets */
      pthread_mutex_unlock(&(agent->mw_ls_mutex));
    }
    EZDBG("%s(%d)\n", __func__, __LINE__);
  }

  /* Stop signal received: somebody called ezcfg_socket_agent_stop. Quit. */
  master_thread_finish(agent);

  return arg;
}

/*
 * Do nothing, since the master_thread_start_routine use agent struct as its arg
 */
static int master_thread_arg_del(void *arg)
{
  return EZCFG_RET_OK;
}

/*
 * stop master thread
 */
static int master_thread_stop(void *arg)
{
  struct ezcfg_socket_agent *agent = NULL;
  struct timespec req;
  struct timespec rem;

  ASSERT(arg != NULL);

  EZDBG("%s(%d)\n", __func__, __LINE__);
  agent = (struct ezcfg_socket_agent *)arg;

  EZDBG("%s(%d)\n", __func__, __LINE__);
  while (agent->master_thread_stop == 0) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    req.tv_sec = EZCFG_AGENT_MASTER_WAIT_TIME;
    req.tv_nsec = 0;
    if (nanosleep(&req, &rem) == -1) {
      EZDBG("%s(%d) errno=[%d]\n", __func__, __LINE__, errno);
      EZDBG("%s(%d) rem.tv_sec=[%ld]\n", __func__, __LINE__, (long)rem.tv_sec);
      EZDBG("%s(%d) rem.tv_nsec=[%ld]\n", __func__, __LINE__, rem.tv_nsec);
    }
    EZDBG("%s(%d)\n", __func__, __LINE__);
  }

  EZDBG("%s(%d)\n", __func__, __LINE__);
  return EZCFG_RET_OK;
}

static int master_thread_is_stopped(struct ezcfg_socket_agent *agent)
{
  if (ezcfg_thread_state_is_stopped(agent->master_thread) == EZCFG_RET_OK) {
    return EZCFG_RET_OK;
  }
  else {
    return EZCFG_RET_OK;
  }
}

static int child_process_list_is_stopped(struct ezcfg_socket_agent *agent)
{
  struct ezcfg_process *process = NULL;
  int list_length = 0;
  int i = 0;
  int ret = EZCFG_RET_FAIL;

  /* lock mutex before handling child_process_list */
  pthread_mutex_lock(&(agent->process_mutex));

  if (agent->child_process_list) {
    list_length = ezcfg_linked_list_get_length(agent->child_process_list);
    for (i = 1; i < list_length+1; i++) {
      process = (struct ezcfg_process *)ezcfg_linked_list_get_node_data_by_index(agent->child_process_list, i);
      if (process == NULL) {
        EZDBG("%s(%d)\n", __func__, __LINE__);
        continue;
      }
      ret = ezcfg_process_state_is_stopped(process);
      if (ret != EZCFG_RET_OK) {
        EZDBG("%s(%d)\n", __func__, __LINE__);
        /* unlock mutex after handling child_process_list */
        pthread_mutex_unlock(&(agent->process_mutex));
        return EZCFG_RET_FAIL;
      }
    }
  }

  /* unlock mutex after handling child_process_list */
  pthread_mutex_unlock(&(agent->process_mutex));
  return EZCFG_RET_OK;
}

/*
 * Deallocate agent environment context, free up the resources
 */
static void env_thread_finish(struct ezcfg_socket_agent *agent)
{
  pthread_mutex_lock(&(agent->env_thread_mutex));

  /* Close all sub_agent environment thread */
  pthread_mutex_lock(&(agent->sub_agent_thread_list_mutex));
  /* FIXME: stop sub-agent environment thread first */
  if (agent->sub_agent_thread_list != NULL) {
    ezcfg_linked_list_del(agent->sub_agent_thread_list);
    agent->sub_agent_thread_list = NULL;
  }
  pthread_mutex_unlock(&(agent->sub_agent_thread_list_mutex));

  /* signal env_thread_stop() that we have done */
  agent->env_thread_stop = 1;

  pthread_mutex_unlock(&(agent->env_thread_mutex));
}

/*
 * Environment thread routine
 */
static void *env_thread_routine(void *arg)
{
  struct ezcfg_socket_agent *agent = NULL;
  struct timespec req;
  struct timespec rem;

  ASSERT(arg != NULL);

  agent = (struct ezcfg_socket_agent *)arg;

  while (ezcfg_thread_state_is_running(agent->env_thread) == EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    req.tv_sec = EZCFG_AGENT_ENVIRONMENT_WAIT_TIME;
    req.tv_nsec = 0;
    if (nanosleep(&req, &rem) == -1) {
      EZDBG("%s(%d) errno=[%d]\n", __func__, __LINE__, errno);
      EZDBG("%s(%d) rem.tv_sec=[%ld]\n", __func__, __LINE__, (long)rem.tv_sec);
      EZDBG("%s(%d) rem.tv_nsec=[%ld]\n", __func__, __LINE__, rem.tv_nsec);
    }
    EZDBG("%s(%d)\n", __func__, __LINE__);
  }

  /* Stop signal received: somebody called ezcfg_socket_agent_stop. Quit. */
  env_thread_finish(agent);

  return arg;
}

/*
 * Do nothing, since the env_thread_start_routine use agent struct as its arg
 */
static int env_thread_arg_del(void *arg)
{
  return EZCFG_RET_OK;
}

/*
 * stop environment thread
 */
static int env_thread_stop(void *arg)
{
  struct ezcfg_socket_agent *agent = NULL;
  struct timespec req;
  struct timespec rem;

  ASSERT(arg != NULL);

  EZDBG("%s(%d)\n", __func__, __LINE__);
  agent = (struct ezcfg_socket_agent *)arg;

  EZDBG("%s(%d)\n", __func__, __LINE__);
  while (agent->env_thread_stop == 0) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    req.tv_sec = EZCFG_AGENT_ENVIRONMENT_WAIT_TIME;
    req.tv_nsec = 0;
    if (nanosleep(&req, &rem) == -1) {
      EZDBG("%s(%d) errno=[%d]\n", __func__, __LINE__, errno);
      EZDBG("%s(%d) rem.tv_sec=[%ld]\n", __func__, __LINE__, (long)rem.tv_sec);
      EZDBG("%s(%d) rem.tv_nsec=[%ld]\n", __func__, __LINE__, rem.tv_nsec);
    }
    EZDBG("%s(%d)\n", __func__, __LINE__);
  }

  EZDBG("%s(%d)\n", __func__, __LINE__);
  return EZCFG_RET_OK;
}

static int agent_stop(struct ezcfg_socket_agent *agent)
{
  int list_length = 0;
  int i = 0;
  int ret = EZCFG_RET_FAIL;
  struct ezcfg_process *process = NULL;

  /* lock mutex before handling child_process_list */
  pthread_mutex_lock(&(agent->process_mutex));

  EZDBG("%s(%d)\n", __func__, __LINE__);
  if (agent->child_process_list) {
    list_length = ezcfg_linked_list_get_length(agent->child_process_list);
    EZDBG("%s(%d) list_length=[%d]\n", __func__, __LINE__, list_length);
    for (i = 1; i < list_length+1; i++) {
      process = (struct ezcfg_process *)ezcfg_linked_list_get_node_data_by_index(agent->child_process_list, i);
      if (process == NULL) {
        EZDBG("%s(%d)\n", __func__, __LINE__);
        continue;
      }
      ret = ezcfg_process_stop(process, SIGTERM);
      if (ret != EZCFG_RET_OK) {
        EZDBG("%s(%d)\n", __func__, __LINE__);
        continue;
      }
    }
  }

  /* unlock mutex after handling child_process_list */
  pthread_mutex_unlock(&(agent->process_mutex));

  /* Stop environment thread */
  EZDBG("%s(%d)\n", __func__, __LINE__);
  if (agent->env_thread) {
    ret = ezcfg_thread_stop(agent->env_thread);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      return EZCFG_RET_FAIL;
    }
  }
 
  /* Stop master thread */
  EZDBG("%s(%d)\n", __func__, __LINE__);
  ret = ezcfg_thread_stop(agent->master_thread);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    return EZCFG_RET_FAIL;
  }
 
  EZDBG("%s(%d)\n", __func__, __LINE__);
  if ((master_thread_is_stopped(agent) == EZCFG_RET_OK) &&
      (child_process_list_is_stopped(agent) == EZCFG_RET_OK)) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    ret = ezcfg_process_state_set_stopped(agent->process);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
    }
    agent->state = AGENT_STATE_STOPPED;
    return EZCFG_RET_OK;
  }
  else {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    return EZCFG_RET_FAIL;
  }
}

static int update_child_process_list(struct ezcfg_socket_agent *agent)
{
  struct ezcfg_process *process = NULL;
  int list_length = 0;
  int i = 0;
  int ret = EZCFG_RET_FAIL;

  /* lock mutex before handling child_process_list */
  pthread_mutex_lock(&(agent->process_mutex));

  if (agent->child_process_list) {
    list_length = ezcfg_linked_list_get_length(agent->child_process_list);
    for (i = 1; i < list_length+1; i++) {
      EZDBG("%s(%d) i=[%d].\n", __func__, __LINE__, i);
      process = (struct ezcfg_process *)ezcfg_linked_list_get_node_data_by_index(agent->child_process_list, i);
      if (process == NULL) {
        EZDBG("%s(%d)\n", __func__, __LINE__);
        continue;
      }
      ret = ezcfg_process_proc_has_no_process(process);
      if (ret == EZCFG_RET_OK) {
        EZDBG("%s(%d) clean i=[%d]\n", __func__, __LINE__, i);
        ret = ezcfg_process_state_set_stopped(process);
        if (ret != EZCFG_RET_OK) {
          EZDBG("%s(%d)\n", __func__, __LINE__);
        }
        ret = ezcfg_linked_list_remove_node_data_by_index(agent->child_process_list, i);
        if (ret != EZCFG_RET_OK) {
          EZDBG("%s(%d) remove i=[%d] error.\n", __func__, __LINE__, i);
        }
        EZDBG("%s(%d) clean done i=[%d]\n", __func__, __LINE__, i);
      }
    }
  }

  /* unlock mutex after handling child_process_list */
  pthread_mutex_unlock(&(agent->process_mutex));
  return EZCFG_RET_OK;
}

static void sigchld_handler(int sig, siginfo_t *si, void *unused)
{
  EZDBG("Got SIGCHLD at address: 0x%lx\n", (long) si->si_addr);
  EZDBG("Got SIGCHLD from pid: %d\n", (int)si->si_pid);
  EZDBG("Got SIGCHLD si_signo: %d\n", (int)si->si_signo);
  EZDBG("Got SIGCHLD si_code: %d\n", (int)si->si_code);
  EZDBG("Got SIGCHLD si_status: %d\n", (int)si->si_status);
  child_process_changed = 1;
}

static void sigterm_handler(int sig, siginfo_t *si, void *unused)
{
  EZDBG("Got SIGTERM at address: 0x%lx\n", (long) si->si_addr);
  EZDBG("Got SIGTERM from pid: %d\n", (int)si->si_pid);
  EZDBG("Got SIGTERM si_signo: %d\n", (int)si->si_signo);
  EZDBG("Got SIGTERM si_code: %d\n", (int)si->si_code);
  EZDBG("Got SIGTERM si_status: %d\n", (int)si->si_status);
  terminate_process = 1;
}

/********************/
/* Public functions */
/**
 * ezcfg_socket_agent_new:
 *
 * Create ezcfg agent.
 *
 * Returns: a new ezcfg agent
 **/
struct ezcfg_socket_agent *ezcfg_socket_agent_new(struct ezcfg *ezcfg)
{
  struct ezcfg_socket_agent *agent;
  int ret = EZCFG_RET_FAIL;
  char *val = NULL;
  struct sigaction sa;

  ASSERT(ezcfg != NULL);

  /* increase ezcfg library context reference */
  if (ezcfg_inc_ref(ezcfg) != EZCFG_RET_OK) {
    EZDBG("ezcfg_inc_ref() failed\n");
    return NULL;
  }

  agent = malloc(sizeof(struct ezcfg_socket_agent));
  if (agent == NULL) {
    err(ezcfg, "calloc ezcfg_socket_agent fail: %m\n");
    /* decrease ezcfg library context reference */
    if (ezcfg_dec_ref(ezcfg) != EZCFG_RET_OK) {
      EZDBG("ezcfg_dec_ref() failed\n");
    }
    return NULL;
  }

  /* initialize agent context */
  memset(agent, 0, sizeof(struct ezcfg_socket_agent));
  agent->state = AGENT_STATE_STOPPED;

  /* Get current process info first */
  EZDBG("%s(%d)\n", __func__, __LINE__);
  ret = ezcfg_common_get_nvram_entry_value(ezcfg, NVRAM_NAME(AGENT, PROCESS_NAMESPACE), &val);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    goto fail_out;
  }
  if (val) {
    agent->process = ezcfg_process_new(ezcfg, val);
    free(val);
    val = NULL;
  }
  if (agent->process == NULL) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "can not initialize agent process info");
    goto fail_out;
  }

  /* There must be an agent master thread to execute action */
  EZDBG("%s(%d)\n", __func__, __LINE__);
  ret = ezcfg_common_get_nvram_entry_value(ezcfg, NVRAM_NAME(AGENT, MASTER_THREAD_NAMESPACE), &val);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    goto fail_out;
  }
  if (val) {
    agent->master_thread = ezcfg_thread_new(ezcfg, val);
    free(val);
    val = NULL;
  }
  if (agent->master_thread == NULL) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "can not initialize agent master thread");
    goto fail_out;
  }

  /* Set the master thread start routine */
  ret = ezcfg_thread_set_start_routine(agent->master_thread, master_thread_routine, agent);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "can not set master thread start routine");
    goto fail_out;
  }

  /*
   * Since agent has been passed to master_thread_routine(),
   * we don't want it been freed when master thread stopped.
   * Here we set an dummy arg delete function to master thread
   */
  ret = ezcfg_thread_set_arg_del_handler(agent->master_thread, master_thread_arg_del);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "can not set master thread arg delete function");
    goto fail_out;
  }

  ret = ezcfg_thread_set_stop(agent->master_thread, master_thread_stop);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "can not set master thread stop function");
    goto fail_out;
  }

  /* There must be an agent worker thread list */
  agent->worker_thread_list = ezcfg_linked_list_new(ezcfg,
      ezcfg_thread_del_handler,
      ezcfg_thread_cmp_handler);
  if (agent->worker_thread_list == NULL) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "can not initialize agent worker thread list");
    goto fail_out;
  }

  /* initialize worker threads */
  EZDBG("%s(%d)\n", __func__, __LINE__);
  agent->worker_threads_max = EZCFG_AGENT_WORKER_THREADS_MAX; /* MAX number of worker threads */
  ret = ezcfg_common_get_nvram_entry_value(ezcfg, NVRAM_NAME(AGENT, WORKER_THREADS_MAX), &val);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
  }
  if (val) {
    agent->worker_threads_max = atoi(val);
    free(val);
    val = NULL;
  }

  /* initialize socket queue */
  EZDBG("%s(%d)\n", __func__, __LINE__);
  agent->mw_sq_len = EZCFG_AGENT_SOCKET_QUEUE_LENGTH;
  ret = ezcfg_common_get_nvram_entry_value(ezcfg, NVRAM_NAME(AGENT, SOCKET_QUEUE_LENGTH), &val);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
  }
  if (val) {
    agent->mw_sq_len = atoi(val);
    free(val);
    val = NULL;
  }
  agent->mw_socket_queue = ezcfg_socket_calloc(ezcfg, agent->mw_sq_len);
  if (agent->mw_socket_queue == NULL) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "calloc socket queue.");
    goto fail_out;
  }

  /*
   * ignore SIGPIPE signal, so if client cancels the request, it
   * won't kill the whole process.
   */
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sa, NULL);
  if (sigaction(SIGPIPE, &sa, NULL) == -1) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "sigaction(SIGPIPE).");
    goto fail_out;
  }

  /*
   * handle SIGCHLD signal, so if child process exits we can update child_process_list
   */
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = sigchld_handler;
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "sigaction(SIGCHLD).");
    goto fail_out;
  }

  /*
   * handle SIGTERM signal, so if process receives termination signal main thread can notify master thread
   */
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = sigterm_handler;
  if (sigaction(SIGTERM, &sa, NULL) == -1) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "sigaction(TERM).");
    goto fail_out;
  }

  /* There must be an sub-agent thread list */
  agent->sub_agent_thread_list = ezcfg_linked_list_new(ezcfg,
      ezcfg_thread_del_handler,
      ezcfg_thread_cmp_handler);
  if (agent->sub_agent_thread_list == NULL) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "can not initialize sub-agent thread list");
    goto fail_out;
  }

  /* initialize thread mutex */
  pthread_mutex_init(&(agent->process_mutex), NULL);
  pthread_mutex_init(&(agent->mw_thread_mutex), NULL);
  pthread_rwlock_init(&(agent->mw_thread_rwlock), NULL);
  pthread_cond_init(&(agent->mw_thread_sync_cond), NULL);
  pthread_mutex_init(&(agent->mw_ls_mutex), NULL);
  pthread_cond_init(&(agent->mw_sq_empty_cond), NULL);
  pthread_cond_init(&(agent->mw_sq_full_cond), NULL);
  pthread_mutex_init(&(agent->env_thread_mutex), NULL);
  pthread_mutex_init(&(agent->sub_agent_thread_list_mutex), NULL);

  /* tag mutex|lock initialized */
  agent->mutex_init = 1;

  /* set ezcfg library context */
  agent->ezcfg = ezcfg;

  /* Successfully create agent */
  return agent;

fail_out:
  EZDBG("%s(%d)\n", __func__, __LINE__);
  if (val) {
    free(val);
  }
  agent_clr(agent);
  free(agent);

  /* decrease ezcfg library context reference */
  if (ezcfg_dec_ref(ezcfg) != EZCFG_RET_OK) {
    EZDBG("ezcfg_dec_ref() failed\n");
  }

  return NULL;
}

/*
 * Deallocate ezcfg agent context, free up the resources
 */
int ezcfg_socket_agent_del(struct ezcfg_socket_agent *agent)
{
  struct ezcfg *ezcfg = NULL;
  int ret = EZCFG_RET_FAIL;

  ASSERT (agent != NULL);

  ezcfg = agent->ezcfg;

  EZDBG("%s(%d)\n", __func__, __LINE__);
  ret = agent_clr(agent);
  EZDBG("%s(%d)\n", __func__, __LINE__);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d) agent_clr() error!\n", __func__, __LINE__);
    return EZCFG_RET_FAIL;
  }

  free(agent);

  /* decrease ezcfg library context reference */
  if (ezcfg_dec_ref(ezcfg) != EZCFG_RET_OK) {
    EZDBG("ezcfg_dec_ref() failed\n");
  }

  return EZCFG_RET_OK;
}

int ezcfg_socket_agent_start(struct ezcfg_socket_agent *agent)
{
  struct ezcfg *ezcfg = NULL;
  struct ezcfg_socket *sp = NULL;
  int ret = EZCFG_RET_FAIL;
  char *val = NULL;
  char ns[EZCFG_NAME_MAX];
  char name[EZCFG_NAME_MAX];
  int sock_num = 0;
  int i = 0;
  struct ezcfg_process *child_process = NULL;
  int child_number = 0;

  ASSERT(agent != NULL);

  EZDBG("%s(%d)\n", __func__, __LINE__);
  ezcfg = agent->ezcfg;
  if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "failed to make us a subreaper: %m");
    if (errno == EINVAL)
      err(ezcfg, "perhaps the kernel version is too old (< 3.4?)");
    return EZCFG_RET_FAIL;
  }

  ret = ezcfg_thread_start(agent->master_thread);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d) ezcfg_thread_start(master_thread) error.\n", __func__, __LINE__);
    return EZCFG_RET_FAIL;
  }

  /* Now we can enable the listening_sockets */
  EZDBG("%s(%d)\n", __func__, __LINE__);
  ret = ezcfg_common_get_nvram_entry_value(ezcfg, NVRAM_NAME(AGENT, SOCKET_NAMESPACE), &val);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    goto fail_out;
  }
  if (val) {
    snprintf(ns, sizeof(ns), "%s", val);
    free(val);
    val = NULL;
  }

  EZDBG("%s(%d)\n", __func__, __LINE__);
  snprintf(name, sizeof(name), "%s%s", ns, NVRAM_NAME(SOCKET, NUMBER));
  ret = ezcfg_common_get_nvram_entry_value(ezcfg, name, &val);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    goto fail_out;
  }
  if (val) {
    sock_num = atoi(val);
    free(val);
    val = NULL;
  }

  EZDBG("%s(%d)\n", __func__, __LINE__);
  for (i = 1; i <= sock_num; i++) {
    EZDBG("%s(%d) i=[%d]\n", __func__, __LINE__, i);
    snprintf(name, sizeof(name), "%s%d.", ns, i);
    sp = ezcfg_socket_new(ezcfg, name);
    if (sp == NULL) {
      err(ezcfg, "init socket fail: %m\n");
      EZDBG("%s(%d) init socket fail: %m\n", __func__, __LINE__);
      goto fail_out;
    }

    if (ezcfg_socket_role_is_server(sp) != EZCFG_RET_OK) {
      EZDBG("%s(%d) socket role is not server\n", __func__, __LINE__);
      ezcfg_socket_del(sp);
      sp = NULL;
      continue;
    }

    /* lock mutex before handling mw_listening_sockets */
    pthread_mutex_lock(&(agent->mw_ls_mutex));

    if (ezcfg_socket_list_insert(&(agent->mw_listening_sockets), sp) < 0) {
      err(ezcfg, "insert listener socket fail: %m\n");
      EZDBG("%s(%d) insert listener socket fail: %m\n", __func__, __LINE__);
      ezcfg_socket_del(sp);
      sp = NULL;
      /* unlock mutex after handling mw_listening_sockets */
      pthread_mutex_unlock(&(agent->mw_ls_mutex));
      goto fail_out;
    }

    if (ezcfg_socket_enable_receiving(sp) < 0) {
      err(ezcfg, "enable socket [%d] receiving fail: %m\n", i);
      EZDBG("%s(%d) enable socket [%d] receiving fail: %m\n", __func__, __LINE__, i);
      ezcfg_socket_list_delete_socket(&(agent->mw_listening_sockets), sp);
      /* unlock mutex after handling mw_listening_sockets */
      pthread_mutex_unlock(&(agent->mw_ls_mutex));
      goto fail_out;
    }

    if (ezcfg_socket_enable_listening(sp, agent->mw_sq_len) < 0) {
      err(ezcfg, "enable socket [%d] listening fail: %m\n", i);
      EZDBG("%s(%d) enable socket [%d] listening fail: %m\n", __func__, __LINE__, i);
      ezcfg_socket_list_delete_socket(&(agent->mw_listening_sockets), sp);
      /* unlock mutex after handling mw_listening_sockets */
      pthread_mutex_unlock(&(agent->mw_ls_mutex));
      goto fail_out;
    }

    ezcfg_socket_set_close_on_exec(sp);
    sp = NULL;

    /* unlock mutex after handling mw_listening_sockets */
    pthread_mutex_unlock(&(agent->mw_ls_mutex));
  }

  /* Prepare child process */
  EZDBG("%s(%d)\n", __func__, __LINE__);
  ret = ezcfg_common_get_nvram_entry_value(ezcfg, NVRAM_NAME(AGENT, CHILD_PROCESS_NAMESPACE), &val);
  if (ret == EZCFG_RET_OK) {
    /* get child process namespace */
    EZDBG("%s(%d)\n", __func__, __LINE__);
    snprintf(ns, sizeof(ns), "%s", val);
    free(val);
    val = NULL;

    /* get child process number */
    ret = ezcfg_util_snprintf_ns_name(name, sizeof(name), ns, NVRAM_NAME(PROCESS, NUMBER));
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      goto fail_out;
    }
    ret = ezcfg_common_get_nvram_entry_value(ezcfg, name, &val);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      goto fail_out;
    }
    if (val) {
      child_number = atoi(val);
      free(val);
      val = NULL;
    }

    /* init child_process_list */
    /* lock mutex before handling child_process_list */
    pthread_mutex_lock(&(agent->process_mutex));

    agent->child_process_list = ezcfg_linked_list_new(ezcfg,
        ezcfg_process_del_handler,
        ezcfg_process_cmp_handler);
    if (agent->child_process_list == NULL) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      /* unlock mutex after handling child_process_list */
      pthread_mutex_unlock(&(agent->process_mutex));
      goto fail_out;
    }

    for (i = 1; i <= child_number; i++) {
      snprintf(name, sizeof(name), "%s%d.", ns, i);
      child_process = ezcfg_process_new(ezcfg, name);
      if (child_process == NULL) {
        EZDBG("%s(%d)\n", __func__, __LINE__);
        err(ezcfg, "can not initialize child process [%d]", i);
        /* unlock mutex after handling child_process_list */
        pthread_mutex_unlock(&(agent->process_mutex));
        goto fail_out;
      }

      /* add to child_process_list */
      ret = ezcfg_linked_list_append(agent->child_process_list, child_process);
      if (ret != EZCFG_RET_OK) {
        EZDBG("%s(%d)\n", __func__, __LINE__);
        /* unlock mutex after handling child_process_list */
        pthread_mutex_unlock(&(agent->process_mutex));
        goto fail_out;
      }
    }

    /* unlock mutex after handling child_process_list */
    pthread_mutex_unlock(&(agent->process_mutex));
  }

  /* Join environment */
  EZDBG("%s(%d)\n", __func__, __LINE__);
  ret = ezcfg_common_get_nvram_entry_value(ezcfg, NVRAM_NAME(AGENT, ENVIRONMENT_NAMESPACE), &val);
  if (ret == EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    /* get environment namespace */
    snprintf(ns, sizeof(ns), "%s", val);
    free(val);
    val = NULL;
    EZDBG("%s(%d) ns=[%s]\n", __func__, __LINE__, ns);

    /* get environment thread namespace */
    ret = ezcfg_util_snprintf_ns_name(name, sizeof(name), ns, NVRAM_NAME(ENVIRONMENT, THREAD_NAMESPACE));
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      goto fail_out;
    }
    EZDBG("%s(%d) name=[%s]\n", __func__, __LINE__, name);
    ret = ezcfg_common_get_nvram_entry_value(ezcfg, name, &val);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      goto fail_out;
    }
    if (val) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      snprintf(name, sizeof(name), "%s", val);
      free(val);
      val = NULL;
    }

    agent->env_thread = ezcfg_thread_new(ezcfg, name);
    if (agent->env_thread == NULL) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      err(ezcfg, "can not initialize agent master thread");
      goto fail_out;
    }

    /* Set the master thread start routine */
    ret = ezcfg_thread_set_start_routine(agent->env_thread, env_thread_routine, agent);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      err(ezcfg, "can not set master thread start routine");
      goto fail_out;
    }

    /*
     * Since agent has been passed to env_thread_routine(),
     * we don't want it been freed when environment thread stopped.
     * Here we set an dummy arg delete function to environment thread
     */
    ret = ezcfg_thread_set_arg_del_handler(agent->env_thread, env_thread_arg_del);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      err(ezcfg, "can not set environment thread arg delete function");
      goto fail_out;
    }

    ret = ezcfg_thread_set_stop(agent->env_thread, env_thread_stop);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      err(ezcfg, "can not set environment thread stop function");
      goto fail_out;
    }

    /* get environment socket namespace */
    EZDBG("%s(%d)\n", __func__, __LINE__);
    ret = ezcfg_util_snprintf_ns_name(name, sizeof(name), ns, NVRAM_NAME(ENVIRONMENT, SOCKET_NAMESPACE));
    if (ret != EZCFG_RET_OK) {
      goto fail_out;
    }
    EZDBG("%s(%d) name=[%s]\n", __func__, __LINE__, name);
    ret = ezcfg_common_get_nvram_entry_value(ezcfg, name, &val);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      goto fail_out;
    }
    if (val) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      snprintf(name, sizeof(name), "%s", val);
      free(val);
      val = NULL;
    }

    agent->env_sp = ezcfg_socket_new(ezcfg, name);
    if (agent->env_sp == NULL) {
      EZDBG("%s(%d) init socket fail: %m\n", __func__, __LINE__);
      err(ezcfg, "init socket fail: %m\n");
      goto fail_out;
    }

    if (ezcfg_socket_role_is_client(agent->env_sp) != EZCFG_RET_OK) {
      EZDBG("%s(%d) socket role is not client\n", __func__, __LINE__);
      goto fail_out;
    }

    ezcfg_socket_set_close_on_exec(agent->env_sp);

    ret = ezcfg_thread_start(agent->env_thread);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d) ezcfg_thread_start(env_thread) error.\n", __func__, __LINE__);
      goto fail_out;
    }
  }

  /* Successfully create agent, wait master_thread to stop */
  EZDBG("%s(%d)\n", __func__, __LINE__);
  agent->state = AGENT_STATE_RUNNING;
  return EZCFG_RET_OK;

fail_out:
  EZDBG("%s(%d)\n", __func__, __LINE__);
  agent->state = AGENT_STATE_STOPPING;
  EZDBG("%s(%d)\n", __func__, __LINE__);
  ret = agent_stop(agent);
  EZDBG("%s(%d)\n", __func__, __LINE__);
  if (ret == EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    agent->state = AGENT_STATE_STOPPED;
  }
  return EZCFG_RET_FAIL;
}

int ezcfg_socket_agent_stop(struct ezcfg_socket_agent *agent)
{
  int ret = EZCFG_RET_FAIL;

  ASSERT(agent != NULL);
  ASSERT(agent->master_thread != NULL);

  if (agent->state == AGENT_STATE_STOPPED) {
    EZDBG("%s(%d) agent already stopped\n", __func__, __LINE__);
    return EZCFG_RET_OK;
  }

  if (agent->state == AGENT_STATE_RUNNING) {
    agent->state = AGENT_STATE_STOPPING;
    ret = agent_stop(agent);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d) agent_stop error.\n", __func__, __LINE__);
      return EZCFG_RET_FAIL;
    }
  }

  if ((master_thread_is_stopped(agent) == EZCFG_RET_OK) &&
      (child_process_list_is_stopped(agent) == EZCFG_RET_OK)) {
    agent->state = AGENT_STATE_STOPPED;
    return EZCFG_RET_OK;
  }
  else {
    return EZCFG_RET_FAIL;
  }
}

int ezcfg_socket_agent_is_running(struct ezcfg_socket_agent *agent)
{
  ASSERT(agent != NULL);

  if (agent->state == AGENT_STATE_RUNNING) {
    return EZCFG_RET_OK;
  }
  else {
    return EZCFG_RET_FAIL;
  }
}

int ezcfg_socket_agent_is_stopped(struct ezcfg_socket_agent *agent)
{
  ASSERT(agent != NULL);

  if (agent->state == AGENT_STATE_STOPPED) {
    return EZCFG_RET_OK;
  }
  else {
    return EZCFG_RET_FAIL;
  }
}

int ezcfg_socket_agent_main_loop(struct ezcfg_socket_agent *agent)
{
  struct timespec req;
  struct timespec rem;
  int ret = EZCFG_RET_FAIL;

  ASSERT(agent != NULL);

  EZDBG("%s(%d)\n", __func__, __LINE__);
  while (agent->state != AGENT_STATE_STOPPED) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    req.tv_sec = EZCFG_AGENT_MASTER_WAIT_TIME;
    req.tv_nsec = 0;
    if (nanosleep(&req, &rem) == -1) {
      EZDBG("%s(%d) errno=[%d]\n", __func__, __LINE__, errno);
      EZDBG("%s(%d) rem.tv_sec=[%ld]\n", __func__, __LINE__, (long)rem.tv_sec);
      EZDBG("%s(%d) rem.tv_nsec=[%ld]\n", __func__, __LINE__, rem.tv_nsec);
    }
    EZDBG("%s(%d)\n", __func__, __LINE__);
    if (terminate_process) {
      ret = agent_stop(agent);
      if (ret != EZCFG_RET_OK) {
        EZDBG("%s(%d) agent_stop() error.\n", __func__, __LINE__);
      }
    }
    EZDBG("%s(%d)\n", __func__, __LINE__);
    if (child_process_changed) {
      child_process_changed = 0;
      ret = update_child_process_list(agent);
      if (ret != EZCFG_RET_OK) {
        EZDBG("%s(%d) update_child_process_list() error.\n", __func__, __LINE__);
      }
    }
  }

  return EZCFG_RET_OK;
}
