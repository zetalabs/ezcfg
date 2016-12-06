/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 *  ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : composite/socket_agent/socket_agent_env_thread.c
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
static int terminate_env_thread = 0; /* flag for receiving SIGUSR1 */

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

static void sigusr1_handler(int sig, siginfo_t *si, void *unused)
{
  EZDBG("Got SIGUSR1 at address: 0x%lx\n", (long) si->si_addr);
  EZDBG("Got SIGUSR1 from pid: %d\n", (int)si->si_pid);
  EZDBG("Got SIGUSR1 si_signo: %d\n", (int)si->si_signo);
  EZDBG("Got SIGUSR1 si_code: %d\n", (int)si->si_code);
  EZDBG("Got SIGUSR1 si_status: %d\n", (int)si->si_status);
  terminate_env_thread = 1;
}

/**************************/
/* local public functions */
/**************************/
/*
 * Environment thread routine
 */
void *local_socket_agent_env_thread_routine(void *arg)
{
  struct ezcfg *ezcfg = NULL;
  struct ezcfg_socket_agent *agent = NULL;
  struct ezcfg_thread *env_thread = NULL;
  struct timespec req;
  struct timespec rem;
  struct sigaction sa;
  sigset_t set;
  int ret;

  ASSERT(arg != NULL);
  agent = (struct ezcfg_socket_agent *)arg;
  ezcfg = agent->ezcfg;

  ASSERT(agent->env_thread != NULL);
  env_thread = agent->env_thread;

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

  /* Block all signals */
  sigfillset(&set);
  sigdelset(&set, SIGUSR1);
  ret = pthread_sigmask(SIG_SETMASK, &set, NULL);
  if (ret != 0) {
    EZDBG("%s(%d) errno=[%d]\n", __func__, __LINE__, errno);
    return arg;
  }

  while (ezcfg_thread_state_is_running(env_thread) == EZCFG_RET_OK) {
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
int local_socket_agent_env_thread_arg_del(void *arg)
{
  return EZCFG_RET_OK;
}

/*
 * stop environment thread
 */
int local_socket_agent_env_thread_stop(void *arg)
{
  struct ezcfg_socket_agent *agent = NULL;
  struct ezcfg_thread *env_thread = NULL;
  struct timespec req;
  struct timespec rem;

  ASSERT(arg != NULL);

  EZDBG("%s(%d)\n", __func__, __LINE__);
  agent = (struct ezcfg_socket_agent *)arg;
  env_thread = agent->env_thread;

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
  /* Since env_thread arg is the struct of agent, to avoid been freed in ezcfg_thread_del(),
   * we set env_thread->arg = NULL here !!!
   */
  ezcfg_thread_set_arg(env_thread, NULL);
  EZDBG("%s(%d)\n", __func__, __LINE__);
  return EZCFG_RET_OK;
}
