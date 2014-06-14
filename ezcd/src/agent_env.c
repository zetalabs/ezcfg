/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 * ============================================================================
 * Project Name : ezbox Configuration Daemon
 * Module Name  : agent_env.c
 *
 * Description  : ezbox agent env
 *
 * Copyright (C) 2008-2014 by ezbox-project
 *
 * History      Rev       Description
 * 2013-07-18   0.1       Write it from scratch
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
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/un.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <syslog.h>
#include <ctype.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>

#include "ezcd.h"

#define handle_error_en(en, msg) \
  do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#if 0
#define DBG(format, args...) do {		  \
    FILE *dbg_fp = fopen("/dev/kmsg", "a");	  \
    if (dbg_fp) {				  \
      fprintf(dbg_fp, format, ## args);		  \
      fclose(dbg_fp);				  \
    }						  \
  } while(0)
#else
#define DBG(format, args...)
#endif

#define INFO(format, args...) do {		   \
    FILE *info_fp = fopen("/dev/kmsg", "a");	   \
    if (info_fp) {				   \
      fprintf(info_fp, format, ## args);	   \
      fclose(info_fp);				   \
    }						   \
  } while(0)


#define AGENT_ENV_PRIORITY	-4

#define AGENT_ENV_CONFIG_FILE_PATH	"/etc/agent/env/default.conf"

#ifndef RB_HALT_SYSTEM
#  define RB_HALT_SYSTEM  0xcdef0123
#  define RB_POWER_OFF    0x4321fedc
#  define RB_AUTOBOOT     0x01234567
#endif

//static bool debug = false;
static int rc = EXIT_FAILURE;
static unsigned int rb = RB_HALT_SYSTEM;
static pthread_t root_thread;
static struct ezcfg_agent *agent = NULL;

static void *sig_thread_routine(void *arg)
{
  sigset_t *set = (sigset_t *) arg;
  int s, sig;

  for (;;) {
    s = sigwait(set, &sig);
    if (s != 0) {
      DBG("<6>agent_env: sigwait errno = [%d]\n", s);
      continue;
    }
    DBG("<6>agent_env: Signal handling thread got signal %d\n", sig);
    switch(sig) {
    case SIGTERM :
    case SIGUSR2 :
      ezcfg_api_agent_stop(agent);
      rc = EXIT_SUCCESS;
      if (sig == SIGTERM)
	rb = RB_AUTOBOOT;
      else
	rb = RB_POWER_OFF;
      return NULL;
    case SIGUSR1 :
      ezcfg_api_agent_reload(agent);
      break;
    case SIGCHLD :
      /* do nothing for child exit */
      break;
    default :
      DBG("<6>agent_env: unknown signal [%d]\n", sig);
      break;
    }
  }

  return NULL;
}

static void init_reap(int sig)
{
  pid_t pid;
  while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
    DBG("<6>agent_env: reaped %d\n", pid);
  }
}

static void init_halt_reboot_poweroff(int sig)
{
  char *p;
  void *handle;
  union {
    rc_function_t func;
    void * obj;
  } alias;
  char *stop_argv[] = { "agent", "env", "stop", NULL };
  sigset_t set;
  pid_t pid;

  /* reset signal handlers */
  signal(SIGUSR1, SIG_DFL);
  signal(SIGTERM, SIG_DFL);
  signal(SIGUSR2, SIG_DFL);
  sigfillset(&set);
  sigprocmask(SIG_UNBLOCK, &set, NULL);

  /* run agent environment stop processes */
  handle = dlopen("/lib/rcso/rc_agent.so", RTLD_NOW);
  if (handle == NULL) {
    DBG("<6>agent_env: dlopen(%s) error %s\n", "/lib/rcso/rc_agent.so", dlerror());
    return;
  }

  /* clear any existing error */
  dlerror();

  alias.obj = dlsym(handle, "rc_agent");

  if ((p = dlerror()) != NULL)  {
    DBG("<6>agent_env: dlsym error %s\n", p);
    dlclose(handle);
    return;
  }

  alias.func(ARRAY_SIZE(stop_argv) - 1, stop_argv);

  /* close loader handle */
  dlclose(handle);

  /* send signals to every process _except_ pid 1 */
  kill(-1, SIGTERM);
  sync();
  sleep(1);

  kill(-1, SIGKILL);
  sync();
  sleep(1);

  p = "halt";
  rb = RB_HALT_SYSTEM;
  if (sig == SIGTERM) {
    p = "reboot";
    rb = RB_AUTOBOOT;
  } else if (sig == SIGUSR2) {
    p = "poweroff";
    rb = RB_POWER_OFF;
  }
  DBG("<6>agent_env: Requesting system %s", p);
  pid = vfork();
  if (pid == 0) { /* child */
    reboot(rb);
    _exit(EXIT_SUCCESS);
  }
  while (1)
    sleep(1);

  /* should never reach here */
  return;
}

int agent_env_main(int argc, char **argv)
{
  char *p;
  void *handle;
  union {
    rc_function_t func;
    void * obj;
  } alias;
  char *boot_argv[]  = { "agent", "env", "boot",  NULL };
  char *start_argv[] = { "agent", "env", "start", NULL };
  char *stop_argv[] = { "agent", "env", "stop", NULL };

  int threads_max = 0;
  int s;
  pthread_t sig_thread;
  sigset_t sigset;

  /* unset umask */
  s = chdir("/");
  umask(0);

  /* make the command line just say "agent_env"  - thats all, nothing else */
  strncpy(argv[0], "agent_env", strlen(argv[0]));
  /* wipe argv[1]-argv[N] so they don't clutter the ps listing */
  while (*++argv)
    memset(*argv, 0, strlen(*argv));

  /* run agent env boot processes */
  handle = dlopen("/lib/rcso/rc_agent.so", RTLD_NOW);
  if (handle == NULL) {
    DBG("<6>agent_env: dlopen(%s) error %s\n", "/lib/rcso/rc_agent.so", dlerror());
    return (EXIT_FAILURE);
  }

  /* clear any existing error */
  dlerror();

  alias.obj = dlsym(handle, "rc_agent");

  if ((p = dlerror()) != NULL)  {
    DBG("<6>agent_env: dlsym error %s\n", p);
    dlclose(handle);
    return (EXIT_FAILURE);
  }

  alias.func(ARRAY_SIZE(boot_argv) - 1, boot_argv);

  /* close loader handle */
  dlclose(handle);

  /* init */
  signal(SIGCHLD, init_reap);
  signal(SIGUSR1, init_halt_reboot_poweroff);
  signal(SIGTERM, init_halt_reboot_poweroff);
  signal(SIGUSR2, init_halt_reboot_poweroff);

  sigemptyset(&sigset);

  if (utils_boot_partition_is_ready() == false) {
    DBG("<6>agent_env: utils_boot_partition_is_ready() == false!\n");
    start_argv[2] = "bootstrap";
  }

  /* run agent env start processes */
  handle = dlopen("/lib/rcso/rc_agent.so", RTLD_NOW);
  if (!handle) {
    DBG("<6>agent_env: dlopen(%s) error %s\n", "/lib/rcso/rc_agent.so", dlerror());
    return (EXIT_FAILURE);
  }

  /* clear any existing error */
  dlerror();

  alias.obj = dlsym(handle, "rc_agent");

  if ((p = dlerror()) != NULL)  {
    DBG("<6>agent_env: dlsym error %s\n", p);
    dlclose(handle);
    return (EXIT_FAILURE);
  }

  alias.func(ARRAY_SIZE(start_argv) - 1, start_argv);

  /* close loader handle */
  dlclose(handle);

  /* run main loop forever */
  /* set scheduling priority for the main daemon process */
  setpriority(PRIO_PROCESS, 0, AGENT_ENV_PRIORITY);

  setsid();

  /* main process */
  INFO("<6>agent_env: booting...\n");
  /* prepare signal handling thread */
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGCHLD);
  sigaddset(&sigset, SIGUSR1);
  sigaddset(&sigset, SIGTERM);
  sigaddset(&sigset, SIGUSR2);
  s = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
  if (s != 0) {
    DBG("<6>agent_env: pthread_sigmask\n");
    handle_error_en(s, "pthread_sigmask");
  }

  /* get root thread id */
  root_thread = pthread_self();

  s = pthread_create(&sig_thread, NULL, &sig_thread_routine, (void *) &sigset);
  if (s != 0) {
    DBG("<6>agent: pthread_create\n");
    handle_error_en(s, "pthread_create");
  }

  if (threads_max < EZCFG_THREAD_MIN_NUM) {
    int memsize = utils_get_mem_size_mb();

    /* set value depending on the amount of RAM */
    if (memsize > 0)
      threads_max = EZCFG_THREAD_MIN_NUM + (memsize / 8);
    else
      threads_max = EZCFG_THREAD_MIN_NUM;
  }

  /* prepare agent master thread */
  if (utils_init_ezcfg_api(AGENT_ENV_CONFIG_FILE_PATH) == false) {
    DBG("<6>agent_env: init ezcfg_api\n");
    return (EXIT_FAILURE);
  }

  agent = ezcfg_api_agent_start("agent_env", threads_max);
  if (agent == NULL) {
    DBG("<6>agent_env: Cannot initialize agent_env\n");
    return (EXIT_FAILURE);
  }

  INFO("<6>agent_env: starting version " VERSION "\n");

  /* wait for exit signal */
  s = pthread_join(sig_thread, NULL);
  if (s != 0) {
    ezcfg_api_agent_stop(agent);
    DBG("<6>agent_env: pthread_join\n");
    handle_error_en(s, "pthread_join");
  }

  /* reset signal handlers */
  signal(SIGUSR1, SIG_DFL);
  signal(SIGTERM, SIG_DFL);
  signal(SIGUSR2, SIG_DFL);
  sigfillset(&sigset);
  sigprocmask(SIG_UNBLOCK, &sigset, NULL);

  /* run agent env stop processes */
  handle = dlopen("/lib/rcso/rc_agent.so", RTLD_NOW);
  if (handle == NULL) {
    DBG("<6>agent_env: dlopen(%s) error %s\n", "/lib/rcso/rc_agent.so", dlerror());
    return (EXIT_FAILURE);
  }

  /* clear any existing error */
  dlerror();

  alias.obj = dlsym(handle, "rc_agent");

  if ((p = dlerror()) != NULL)  {
    DBG("<6>agent_env: dlsym error %s\n", p);
    dlclose(handle);
    return (EXIT_FAILURE);
  }

  alias.func(ARRAY_SIZE(stop_argv) - 1, stop_argv);

  /* close loader handle */
  dlclose(handle);

  /* send signals to every process _except_ pid 1 */
  kill(-1, SIGTERM);
  sync();
  sleep(1);

  kill(-1, SIGKILL);
  sync();
  sleep(1);

  if (rb == RB_HALT_SYSTEM)
    p = "halt";
  else if (rb == RB_AUTOBOOT)
    p = "reboot";
  else if (rb == RB_POWER_OFF)
    p = "poweroff";
  DBG("<6>agent_env: Requesting system %s", p);
  if (vfork() == 0) {
    /* child */
    reboot(rb);
    _exit(EXIT_SUCCESS);
  }
  while (1)
    sleep(1);

  /* should never run to this place!!! */
  return (EXIT_FAILURE);
}
