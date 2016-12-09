/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 *  ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : composite/socket_agent/socket_agent_master_thread.c
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2016 by ezbox-project
 *
 * History      Rev       Description
 * 2015-12-29   0.1       Split it from socket_agent.c
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
#include <signal.h>
#include <sys/prctl.h>

#include "ezcfg.h"
#include "ezcfg-private.h"

#include "socket_agent_local.h"

/* Private variables */
static int terminate_master_thread = 0; /* flag for receiving SIGUSR1 */

/* Private functions */
static void add_to_set(int fd, fd_set *set, int *max_fd)
{
  FD_SET(fd, set);
  if (fd > *max_fd) {
    *max_fd = (int) fd;
  }
}

/* Master thread adds accepted socket to a queue */
static int put_socket(struct ezcfg_socket_agent *agent, struct ezcfg_socket *sp)
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
      EZDBG("%s(%d) Cannot prepare worker thread\n", __func__, __LINE__);
      err(ezcfg, "Cannot prepare worker thread: %m\n");
      goto func_out;
    }

    worker_thread_arg = malloc(sizeof(struct worker_thread_arg));
    if (worker_thread_arg == NULL) {
      EZDBG("%s(%d) Cannot prepare worker thread arg\n", __func__, __LINE__);
      err(ezcfg, "Cannot prepare worker thread arg: %m\n");
      goto func_out;
    }
    memset(worker_thread_arg, 0, sizeof(struct worker_thread_arg));
    worker_thread_arg->agent = agent;
    worker_thread_arg->worker_thread = worker_thread;
    worker_thread_arg->sp = ezcfg_socket_new_dummy(ezcfg);
    if (worker_thread_arg->sp == NULL) {
      EZDBG("%s(%d) Cannot prepare worker thread arg dummy socket\n", __func__, __LINE__);
      err(ezcfg, "Cannot prepare worker thread arg dummy socket: %m\n");
      goto func_out;
    }
    //worker_thread_arg->proto = proto;
    //worker_thread_arg->proto_data = proto_data;
    //worker_thread_arg->birth_time = birth_time;
    //worker_thread_arg->num_bytes_sent = num_bytes_sent;

    /* Set the worker thread start routine */
    ret = ezcfg_thread_set_start_routine(worker_thread, local_socket_agent_worker_thread_routine, worker_thread_arg);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      err(ezcfg, "can not set worker thread start routine");
      goto func_out;
    }

    /*
     * Since agent has been passed to worker_thread_routine(),
     * we don't want it been freed when worker thread stopped.
     * Here we set an dummy arg delete function to worker thread
     */
    ret = ezcfg_thread_set_arg_del_handler(worker_thread, local_socket_agent_worker_thread_arg_del);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      err(ezcfg, "can not set worker thread arg delete function");
      goto func_out;
    }

    ret = ezcfg_thread_set_stop(worker_thread, local_socket_agent_worker_thread_stop);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      err(ezcfg, "can not set worker thread stop function");
      goto func_out;
    }

    /* add to worker list */
    ret = ezcfg_linked_list_append(agent->worker_thread_list, worker_thread);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      goto func_out;
    }
    /* we increase agent->num_worker_threads in local_socket_agent_worker_thread_routine() */
    //agent->num_worker_threads++;

    ret = ezcfg_thread_start(worker_thread);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d) Cannot start thread: %m\n", __func__, __LINE__);
      err(ezcfg, "Cannot start thread: %m\n");
      ret = ezcfg_linked_list_remove(agent->worker_thread_list, worker_thread);
      if (ret != EZCFG_RET_OK) {
        EZDBG("%s(%d)\n", __func__, __LINE__);
        goto func_out;
      }
      EZDBG("%s(%d)\n", __func__, __LINE__);
      /* we decrease agent->num_worker_threads in local_socket_agent_worker_thread_routine() */
      //agent->num_worker_threads--;
      /* worker_thread_arg and worker_thread have been freed in ezcfg_linked_list_remove() */
      worker_thread_arg = NULL;
      worker_thread = NULL;
      ret = EZCFG_RET_FAIL;
      goto func_out;
    }
    /* worker_thread_arg has been put to worker_thread */
    worker_thread_arg = NULL;
    /* worker_thread has been appened to agent->worker_thread_list */
    worker_thread = NULL;
  }
  EZDBG("%s(%d)\n", __func__, __LINE__);
  ret = EZCFG_RET_OK;

func_out:
  if (worker_thread) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    ezcfg_thread_del(worker_thread);
    EZDBG("%s(%d)\n", __func__, __LINE__);
    worker_thread_arg = NULL;
    worker_thread = NULL;
    EZDBG("%s(%d)\n", __func__, __LINE__);
  }

  if (worker_thread_arg) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    local_socket_agent_worker_thread_arg_del(worker_thread_arg);
    EZDBG("%s(%d)\n", __func__, __LINE__);
    free(worker_thread_arg);
    EZDBG("%s(%d)\n", __func__, __LINE__);
    worker_thread_arg = NULL;
    EZDBG("%s(%d)\n", __func__, __LINE__);
  }

#if 0
  if (agent->num_worker_threads == 0) {
    /* no worker thread !!! */
    agent->mw_sq_head--;
    ret = EZCFG_RET_FAIL;
  }
#endif

  EZDBG("%s(%d)\n", __func__, __LINE__);
  pthread_cond_signal(&(agent->mw_sq_empty_cond));
  EZDBG("%s(%d)\n", __func__, __LINE__);
  pthread_mutex_unlock(&(agent->mw_thread_mutex));
  EZDBG("%s(%d)\n", __func__, __LINE__);
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
    EZDBG("%s(%d) ret=[%d]\n", __func__, __LINE__, ret);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d) put_socket() accepted socket error.\n", __func__, __LINE__);
      err(ezcfg, "put_socket() accepted socket error.\n");
      ezcfg_socket_del(accepted);
    }
    else {
      /* we don't use ezcfg_socket_del() because accepted->sock has been put into queue in put_socket() */
      free(accepted);
    }
    EZDBG("%s(%d)\n", __func__, __LINE__);
  }
  else {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    ezcfg_socket_del(accepted);
    EZDBG("%s(%d)\n", __func__, __LINE__);
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
    EZDBG("%s(%d)\n", __func__, __LINE__);
  }
  agent->worker_threads_max = 0;

  pthread_mutex_unlock(&(agent->mw_thread_mutex));

  /* signal master_thread_stop() that we have done */
  agent->master_thread_stop = 1;
}

static void sigusr1_handler(int sig, siginfo_t *si, void *unused)
{
  EZDBG("Got SIGUSR1 at address: 0x%lx\n", (long) si->si_addr);
  EZDBG("Got SIGUSR1 from pid: %d\n", (int)si->si_pid);
  EZDBG("Got SIGUSR1 si_signo: %d\n", (int)si->si_signo);
  EZDBG("Got SIGUSR1 si_code: %d\n", (int)si->si_code);
  EZDBG("Got SIGUSR1 si_status: %d\n", (int)si->si_status);
  terminate_master_thread = 1;
}

/********************/
/* local public functions */
/********************/
void *local_socket_agent_master_thread_routine(void *arg)
{
  struct ezcfg_socket_agent *agent = NULL;
  struct ezcfg_thread *master_thread = NULL;
  fd_set read_set;
  struct ezcfg *ezcfg;
  struct ezcfg_socket *sp;
  struct timespec ts;
  int max_fd;
  int retval;
  struct sigaction sa;
  sigset_t set;
  int ret;

  ASSERT(arg != NULL);
  agent = (struct ezcfg_socket_agent *)arg;
  ezcfg = agent->ezcfg;

  ASSERT(agent->master_thread != NULL);
  master_thread = agent->master_thread;

  /*
   * handle SIGUSR1 signal
   */
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = sigusr1_handler;
  if (sigaction(SIGUSR1, &sa, NULL) == -1) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "sigaction(USR1).");
    return arg;
  }

  /* Block all signals except SIGUSR1 */
  sigfillset(&set);
  sigdelset(&set, SIGUSR1);
  ret = pthread_sigmask(SIG_SETMASK, &set, NULL);
  if (ret != 0) {
    EZDBG("%s(%d) errno=[%d]\n", __func__, __LINE__, errno);
    return arg;
  }

  while (ezcfg_thread_state_is_running(master_thread) == EZCFG_RET_OK) {
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
    ts.tv_sec = EZCFG_AGENT_MASTER_WAIT_TIME;
    ts.tv_nsec = 0;

    retval = pselect(max_fd + 1, &read_set, NULL, NULL, &ts, &set);
    if (retval == -1) {
      perror("pselect()");
      err(ezcfg, "pselect() %m\n");
      if (terminate_master_thread) {
        EZDBG("%s(%d)\n", __func__, __LINE__);
        break;
      }
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
            EZDBG("%s(%d) accept_new_connection() failed\n", __func__, __LINE__);

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
  EZDBG("%s(%d)\n", __func__, __LINE__);
  master_thread_finish(agent);
  EZDBG("%s(%d)\n", __func__, __LINE__);

  //return arg;
  return NULL;
}

/*
 * Do nothing, since the master_thread_start_routine use agent struct as its arg
 */
int local_socket_agent_master_thread_arg_del(void *arg)
{
  EZDBG("%s(%d)\n", __func__, __LINE__);
  return EZCFG_RET_OK;
}

/*
 * stop master thread
 */
int local_socket_agent_master_thread_stop(void *arg)
{
  struct ezcfg_socket_agent *agent = NULL;
  struct ezcfg_thread *master_thread = NULL;
  struct timespec req;
  struct timespec rem;

  ASSERT(arg != NULL);

  EZDBG("%s(%d)\n", __func__, __LINE__);
  agent = (struct ezcfg_socket_agent *)arg;
  master_thread = agent->master_thread;

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
  /* Since master_thread arg is the struct of agent, to avoid been freed in ezcfg_thread_del(),
   * we set master_thread->arg = NULL here !!!
   */
  ezcfg_thread_set_arg(master_thread, NULL);
  EZDBG("%s(%d)\n", __func__, __LINE__);
  return EZCFG_RET_OK;
}

int local_socket_agent_master_thread_is_stopped(struct ezcfg_socket_agent *agent)
{
  ASSERT(agent != NULL);
  ASSERT(agent->master_thread != NULL);

  if (ezcfg_thread_state_is_stopped(agent->master_thread) == EZCFG_RET_OK) {
    return EZCFG_RET_OK;
  }
  else {
    return EZCFG_RET_OK;
  }
}

