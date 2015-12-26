/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 *  ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : composite/socket_agent/socket_agent.c
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2014 by ezbox-project
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

#ifndef PR_SET_CHILD_SUBREAPER
#define PR_SET_CHILD_SUBREAPER 36
#endif

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

  struct ezcfg_process *process;
  struct ezcfg_linked_list *child_process_list;

  struct ezcfg_thread *master_thread;
  struct ezcfg_linked_list *worker_thread_list;

  sigset_t *sigset;

  int thread_stop; /* master thread stop flag */
  int threads_max; /* MAX number of worker threads */
  int num_threads; /* Number of worker threads */
  int num_idle_threads; /* Number of idle worker threads */

  int mutex_init; /* mutex|lock init flag */

  pthread_mutex_t process_mutex; /* Protects child_process_list */

  pthread_mutex_t thread_mutex; /* Protects (max|num)_threads */
  pthread_rwlock_t thread_rwlock; /* Protects options, callbacks */
  pthread_cond_t thread_sync_cond; /* Condvar for thread sync */

  struct ezcfg_socket *listening_sockets;
  pthread_mutex_t ls_mutex; /* Protects listening_sockets */

  struct ezcfg_socket *queue; /* Accepted sockets */
  int sq_len; /* Length of the socket queue */
  int sq_head; /* Head of the socket queue */
  int sq_tail; /* Tail of the socket queue */
  pthread_cond_t sq_empty_cond; /* Socket queue empty condvar */
  pthread_cond_t sq_full_cond;  /* Socket queue full condvar */
};

/* Private variables */
static int child_process_changed = 0; /* flag for receiving SIGCHLD */

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
    pthread_cond_destroy(&(agent->sq_empty_cond));
    pthread_cond_destroy(&(agent->sq_full_cond));

    pthread_mutex_destroy(&(agent->ls_mutex));

    pthread_cond_destroy(&(agent->thread_sync_cond));
    pthread_rwlock_destroy(&(agent->thread_rwlock));
    pthread_mutex_destroy(&(agent->thread_mutex));
    pthread_mutex_destroy(&(agent->process_mutex));
  }

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

  ASSERT(agent != NULL);
  ASSERT(sp != NULL);

  ezcfg = agent->ezcfg;

  pthread_mutex_lock(&(agent->thread_mutex));

  /* If the queue is full, wait */
  while (agent->sq_head - agent->sq_tail >= agent->sq_len) {
    pthread_cond_wait(&(agent->sq_full_cond), &(agent->thread_mutex));
  }
  ASSERT(agent->sq_head - agent->sq_tail < agent->sq_len);

  /* Copy socket to the queue and increment head */
  ezcfg_socket_queue_set_socket(agent->queue, agent->sq_head % agent->sq_len, sp);
  agent->sq_head++;

  /* If there is no idle thread, start one */
  if (agent->num_idle_threads == 0 && agent->num_threads < agent->threads_max) {
    struct ezcfg_thread *worker_thread = NULL;

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
    ret = ezcfg_thread_start(worker_thread);
    if (ret != EZCFG_RET_OK) {
      err(ezcfg, "Cannot start thread: %m\n");
      goto func_out;
    }
    /* add to worker list */
    ret = ezcfg_linked_list_append(agent->worker_thread_list, worker_thread);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      goto func_out;
    }
    agent->num_threads++;
  }
  ret = EZCFG_RET_OK;

func_out:
  pthread_cond_signal(&(agent->sq_empty_cond));
  pthread_mutex_unlock(&(agent->thread_mutex));
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

  pthread_mutex_lock(&(agent->thread_mutex));

  /* Close all listening sockets */
  pthread_mutex_lock(&(agent->ls_mutex));
  if (agent->listening_sockets != NULL) {
    ezcfg_socket_list_delete(&(agent->listening_sockets));
    agent->listening_sockets = NULL;
  }
  pthread_mutex_unlock(&(agent->ls_mutex));

  /* Close all workers' socket */
#if 0
  worker_thread = agent->worker_thread_list;
  while (worker != NULL) {
    ezcfg_worker_close_connection(worker);
    worker = ezcfg_worker_get_next(worker);
  }
#endif

  /* Wait until all threads finish */
  while (agent->num_threads > 0) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    pthread_cond_wait(&(agent->thread_sync_cond), &(agent->thread_mutex));
  }
  agent->threads_max = 0;

  pthread_mutex_unlock(&(agent->thread_mutex));

  /* signal master_thread_stop() that we have done */
  agent->thread_stop = 1;
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
    /* lock mutex before handling listening_sockets */
    pthread_mutex_lock(&(agent->ls_mutex));

    for (sp = agent->listening_sockets; sp != NULL; sp = ezcfg_socket_list_next(&sp)) {
      add_to_set(ezcfg_socket_get_sock(sp), &read_set, &max_fd);
    }

    /* unlock mutex after handling listening_sockets */
    pthread_mutex_unlock(&(agent->ls_mutex));

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
      /* lock mutex before handling listening_sockets */
      pthread_mutex_lock(&(agent->ls_mutex));

      for (sp = agent->listening_sockets;
           sp != NULL;
           sp = ezcfg_socket_list_next(&sp)) {
        if (FD_ISSET(ezcfg_socket_get_sock(sp), &read_set)) {
          if (accept_new_connection(agent, sp) != EZCFG_RET_OK) {
            /* re-enable the socket */
            err(ezcfg, "accept_new_connection() failed\n");

            if (ezcfg_socket_enable_again(sp) < 0) {
              err(ezcfg, "ezcfg_socket_enable_again() failed\n");
              ezcfg_socket_list_delete_socket(&(agent->listening_sockets), sp);
            }
          }
        }
      }

      /* unlock mutex after handling listening_sockets */
      pthread_mutex_unlock(&(agent->ls_mutex));
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
  while (agent->thread_stop == 0) {
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

  /* Then stop master thread */
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
  agent->threads_max = EZCFG_AGENT_WORKER_THREADS_MAX; /* MAX number of worker threads */
  ret = ezcfg_common_get_nvram_entry_value(ezcfg, NVRAM_NAME(AGENT, WORKER_THREADS_MAX), &val);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
  }
  if (val) {
    agent->threads_max = atoi(val);
    free(val);
    val = NULL;
  }

  /* initialize socket queue */
  EZDBG("%s(%d)\n", __func__, __LINE__);
  agent->sq_len = EZCFG_AGENT_SOCKET_QUEUE_LENGTH;
  ret = ezcfg_common_get_nvram_entry_value(ezcfg, NVRAM_NAME(AGENT, SOCKET_QUEUE_LENGTH), &val);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
  }
  if (val) {
    agent->sq_len = atoi(val);
    free(val);
    val = NULL;
  }
  agent->queue = ezcfg_socket_calloc(ezcfg, agent->sq_len);
  if (agent->queue == NULL) {
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
   * handle SIGCHLD signal, so if child process exit we can update child_process_list
   */
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = sigchld_handler;
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "sigaction(SIGCHLD).");
    goto fail_out;
  }

  /* initialize thread mutex */
  pthread_mutex_init(&(agent->process_mutex), NULL);
  pthread_mutex_init(&(agent->thread_mutex), NULL);
  pthread_rwlock_init(&(agent->thread_rwlock), NULL);
  pthread_cond_init(&(agent->thread_sync_cond), NULL);
  pthread_mutex_init(&(agent->ls_mutex), NULL);
  pthread_cond_init(&(agent->sq_empty_cond), NULL);
  pthread_cond_init(&(agent->sq_full_cond), NULL);

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
  char socket_ns[EZCFG_NAME_MAX];
  char name[EZCFG_NAME_MAX];
  int sock_num = 0;
  int i = 0;
  struct ezcfg_process *child_process = NULL;
  char cp_ns[EZCFG_NAME_MAX];
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
    EZDBG("%s(%d) ezcfg_thread_start() error.\n", __func__, __LINE__);
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
    snprintf(socket_ns, sizeof(socket_ns), "%s", val);
    free(val);
    val = NULL;
  }

  EZDBG("%s(%d)\n", __func__, __LINE__);
  snprintf(name, sizeof(name), "%s%s", socket_ns, NVRAM_NAME(SOCKET, NUMBER));
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
    snprintf(name, sizeof(name), "%s%d.", socket_ns, i);
    sp = ezcfg_socket_new(ezcfg, name);
    if (sp == NULL) {
      err(ezcfg, "init socket fail: %m\n");
      EZDBG("%s(%d) init socket fail: %m\n", __func__, __LINE__);
      goto fail_out;
    }

    /* lock mutex before handling listening_sockets */
    pthread_mutex_lock(&(agent->ls_mutex));

    if (ezcfg_socket_list_insert(&(agent->listening_sockets), sp) < 0) {
      err(ezcfg, "insert listener socket fail: %m\n");
      EZDBG("%s(%d) insert listener socket fail: %m\n", __func__, __LINE__);
      ezcfg_socket_del(sp);
      sp = NULL;
      /* unlock mutex after handling listening_sockets */
      pthread_mutex_unlock(&(agent->ls_mutex));
      goto fail_out;
    }

    if (ezcfg_socket_enable_receiving(sp) < 0) {
      err(ezcfg, "enable socket [%d] receiving fail: %m\n", i);
      EZDBG("%s(%d) enable socket [%d] receiving fail: %m\n", __func__, __LINE__, i);
      ezcfg_socket_list_delete_socket(&(agent->listening_sockets), sp);
      /* unlock mutex after handling listening_sockets */
      pthread_mutex_unlock(&(agent->ls_mutex));
      goto fail_out;
    }

    if (ezcfg_socket_enable_listening(sp, agent->sq_len) < 0) {
      err(ezcfg, "enable socket [%d] listening fail: %m\n", i);
      EZDBG("%s(%d) enable socket [%d] listening fail: %m\n", __func__, __LINE__, i);
      ezcfg_socket_list_delete_socket(&(agent->listening_sockets), sp);
      /* unlock mutex after handling listening_sockets */
      pthread_mutex_unlock(&(agent->ls_mutex));
      goto fail_out;
    }

    ezcfg_socket_set_close_on_exec(sp);
    sp = NULL;

    /* unlock mutex after handling listening_sockets */
    pthread_mutex_unlock(&(agent->ls_mutex));
  }

  /* Prepare child process */
  EZDBG("%s(%d)\n", __func__, __LINE__);
  ret = ezcfg_common_get_nvram_entry_value(ezcfg, NVRAM_NAME(AGENT, CHILD_PROCESS_NAMESPACE), &val);
  if (ret == EZCFG_RET_OK) {
    /* get child process namespace */
    EZDBG("%s(%d)\n", __func__, __LINE__);
    snprintf(cp_ns, sizeof(cp_ns), "%s", val);
    free(val);
    val = NULL;

    /* get child process number */
    ret = ezcfg_util_snprintf_ns_name(name, sizeof(name), cp_ns, NVRAM_NAME(PROCESS, NUMBER));
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
      snprintf(name, sizeof(name), "%s%d.", cp_ns, i);
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
    if (child_process_changed) {
      child_process_changed = 0;
      update_child_process_list(agent);
    }
  }

  return EZCFG_RET_OK;
}
