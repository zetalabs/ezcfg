/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 * ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : basic/process/process.c
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2015 by ezbox-project
 *
 * History      Rev       Description
 * 2015-06-11   0.1       Write it from scratch
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
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "ezcfg.h"
#include "ezcfg-private.h"

/* bitmap for process state */
#define PROCESS_STATE_STOPPED     0
#define PROCESS_STATE_RUNNING     1
#define PROCESS_STATE_STOPPING    2

/*
 * ezcfg-process - ezbox config process model
 *
 */

struct ezcfg_process {
  struct ezcfg *ezcfg;
  pthread_mutex_t process_mutex;
  pid_t process_id; /* process's own pid */
  char *command; /* process command */
  int state; /* process state */
  int force_stop; /* force to stop process in force_stop seconds */
};

/**
 * private functions
 */
static char *get_pid_command(pid_t pid)
{
  FILE *fp = NULL;
  char buf[256];
  char *cmd = NULL;

  snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
  fp = fopen(buf, "r");
  if (!fp) {
    EZDBG("fopen %s failed\n", buf);
    return NULL;
  }
  buf[0] = '\0';
  cmd = fgets(buf, sizeof(buf), fp);
  fclose(fp);
  if (cmd == NULL) {
    EZDBG("fgets failed errno=[%d]\n", errno);
    return NULL;
  }
  cmd = strdup(buf);
  if (cmd == NULL) {
    EZDBG("strdup %s failed\n", buf);
  }
  return cmd;
}

static int proc_has_no_process(struct ezcfg_process *process)
{
  FILE *fp = NULL;
  char buf[256];
  char *cmd = NULL;

  snprintf(buf, sizeof(buf), "/proc/%d/cmdline", process->process_id);
  fp = fopen(buf, "r");
  if (!fp) {
    EZDBG("can not fopen %s\n", buf);
    return EZCFG_RET_OK;
  }
  buf[0] = '\0';
  cmd = fgets(buf, sizeof(buf), fp);
  fclose(fp);
  if (cmd == NULL) {
    EZDBG("fgets failed errno=[%d]\n", errno);
    return EZCFG_RET_OK;
  }
  if (strcmp(buf, process->command) == 0) {
    return EZCFG_RET_FAIL;
  }
  else {
    return EZCFG_RET_OK;
  }
}

/**
 * public functions
 */
struct ezcfg_process *ezcfg_process_new(struct ezcfg *ezcfg, char *ns)
{
  struct ezcfg_process *process = NULL;
  char name[EZCFG_NAME_MAX] = "";
  char *val = NULL;
  int ret = EZCFG_RET_FAIL;
  int i = 0;
  int need_fork = 0;
  int argc = 0;
  char **argv = NULL;
  int force_stop = 0;
  int my_errno = 0;
  int sig = 0;
  int fd= -1;
  struct sigaction sa;

  ASSERT (ezcfg != NULL);
  ASSERT (ns != NULL);

  /* increase ezcfg library context reference */
  if (ezcfg_inc_ref(ezcfg) != EZCFG_RET_OK) {
    EZDBG("ezcfg_inc_ref() failed\n");
    return NULL;
  }

  process = (struct ezcfg_process *)calloc(1, sizeof(struct ezcfg_process));
  if (process == NULL) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    err(ezcfg, "can not calloc process\n");
    goto exit_fail;
  }

  /* first check if it need to be forked */
  ret = ezcfg_util_snprintf_ns_name(name, sizeof(name), ns, NVRAM_NAME(PROCESS, FORK));
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    goto exit_fail;
  }
  ret = ezcfg_common_get_nvram_entry_value(ezcfg, name, &val);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    goto exit_fail;
  }
  if (val) {
    need_fork = atoi(val);
    free(val);
    val = NULL;
  }

  if (need_fork == 0) {
    /* handle no fork case */
    EZDBG("%s(%d)\n", __func__, __LINE__);
    process->process_id = getpid();
    process->command = get_pid_command(process->process_id);
    if (process->command == NULL) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      err(ezcfg, "can not get process command\n");
      goto exit_fail;
    }
    pthread_mutex_init(&(process->process_mutex), NULL);
    process->state = PROCESS_STATE_RUNNING;
    process->force_stop = force_stop;
    process->ezcfg = ezcfg;
    EZDBG("%s(%d) pid=[%d] cmd=[%s]\n", __func__, __LINE__, process->process_id, process->command);
    return process;
  }
  else {
    /* prepare information for new process */
    ret = ezcfg_util_snprintf_ns_name(name, sizeof(name), ns, NVRAM_NAME(PROCESS, ARGC));
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      goto exit_fail;
    }
    ret = ezcfg_common_get_nvram_entry_value(ezcfg, name, &val);
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      goto exit_fail;
    }
    if (val) {
      argc = atoi(val);
      free(val);
      val = NULL;
    }
    if (argc < 1) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      goto exit_fail;
    }
    argv = (char **)calloc(argc+1, sizeof(char *));
    if (argv == NULL) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      goto exit_fail;
    }
    for (i = 1; i <= argc; i++) {
      snprintf(name, sizeof(name), "%s%s.%d", ns, NVRAM_NAME(PROCESS, ARGV), i);
      ret = ezcfg_common_get_nvram_entry_value(ezcfg, name, &val);
      if (ret != EZCFG_RET_OK) {
        EZDBG("%s(%d)\n", __func__, __LINE__);
        goto exit_fail;
      }
      if (val) {
        argv[i-1] = val;
        val = NULL;
      }
    }
    /* If set command, put it to process->command */
    ret = ezcfg_util_snprintf_ns_name(name, sizeof(name), ns, NVRAM_NAME(PROCESS, COMMAND));
    if (ret != EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      goto exit_fail;
    }
    ret = ezcfg_common_get_nvram_entry_value(ezcfg, name, &val);
    if (ret == EZCFG_RET_OK) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      process->command = val;
      val = NULL;
    }
  }

  ret = ezcfg_util_snprintf_ns_name(name, sizeof(name), ns, NVRAM_NAME(PROCESS, FORCE_STOP));
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
    goto exit_fail;
  }
  ret = ezcfg_common_get_nvram_entry_value(ezcfg, name, &val);
  if (ret != EZCFG_RET_OK) {
    EZDBG("%s(%d)\n", __func__, __LINE__);
  }
  if (val) {
    force_stop = atoi(val);
    free(val);
    val = NULL;
  }

  /* handle fork case */
  process->process_id = fork();
  switch(process->process_id) {
  case -1:
    /* it's in original process runtime space */
    EZDBG("%s(%d)\n", __func__, __LINE__);
    my_errno = errno;
    err(ezcfg, "can not fork, errno=[%d]\n", my_errno);
    goto exit_fail;

  case 0:
    /* it's in child process runtime space */
    /* cleanup parent process resources */
    if (process->command) {
      free(process->command);
      process->command = NULL;
    }
    free(process);
    process = NULL;

    /* reset signal handlers set from parent process */
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_DFL;
    for (sig = 0; sig < (_NSIG-1); sig++) {
      if ((sig == SIGKILL) ||(sig == SIGSTOP))
        continue;
      if (sigaction(sig, &sa, NULL) == -1) {
        EZDBG("%s(%d) sigaction(%d) error.\n", __func__, __LINE__, sig);
      }
    }

    /* clean up */
    ioctl(0, TIOCNOTTY, 0);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    setsid();

    /* check if /dev/console is available */
    if ((fd = open("/dev/console", O_RDWR)) < 0) {
      (void) open("/dev/null", O_RDONLY);
      (void) open("/dev/null", O_WRONLY);
      (void) open("/dev/null", O_WRONLY);
    }
    else {
      close(fd);
      (void) open("/dev/console", O_RDONLY);
      (void) open("/dev/console", O_WRONLY);
      (void) open("/dev/console", O_WRONLY);
    }

    /* execute command */
    setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin", 1);
    execvp(argv[0], argv);
    perror(argv[0]);
    exit(errno);

  default:
    /* it's in parent process runtime space */
    /* cleanup unused variables */
    if (argv != NULL) {
      if (process->command == NULL) {
        process->command = argv[0];
        argv[0] = NULL;
      }
      for (i = 0; i < argc; i++) {
        if (argv[i] != NULL) {
          free(argv[i]);
          argv[i] = NULL;
        }
      }
      free(argv);
      argv = NULL;
    }

    /* set child process info */
    pthread_mutex_init(&(process->process_mutex), NULL);
    process->state = PROCESS_STATE_RUNNING;
    process->force_stop = force_stop;
    process->ezcfg = ezcfg;
    EZDBG("%s(%d) child pid=[%d] cmd=[%s]\n", __func__, __LINE__, process->process_id, process->command);
    return process;
  }

exit_fail:
  EZDBG("%s(%d)\n", __func__, __LINE__);
  if (argv != NULL) {
    for (i = 0; i < argc; i++) {
      if (argv[i] != NULL) {
        free(argv[i]);
        argv[i] = NULL;
      }
    }
    free(argv);
    argv = NULL;
  }
  if (process != NULL) {
    if (process->command) {
      free(process->command);
      process->command = NULL;
    }
    free(process);
    process = NULL;
  }
  /* decrease ezcfg library context reference */
  if (ezcfg_dec_ref(ezcfg) != EZCFG_RET_OK) {
    EZDBG("ezcfg_dec_ref() failed\n");
  }
  return process;
}

int ezcfg_process_del(struct ezcfg_process *process)
{
  struct ezcfg *ezcfg = NULL;

  ASSERT(process != NULL);

  ezcfg = process->ezcfg;

  if (process->state != PROCESS_STATE_STOPPED) {
    EZDBG("process must stop first\n");
    return EZCFG_RET_FAIL;
  }

  if (process->command) {
    free(process->command);
    process->command = NULL;
  }
  free(process);

  /* decrease ezcfg library context reference */
  if (ezcfg_dec_ref(ezcfg) != EZCFG_RET_OK) {
    EZDBG("ezcfg_dec_ref() failed\n");
  }
  return EZCFG_RET_OK;
}

int ezcfg_process_stop(struct ezcfg_process *process, int sig)
{
  int ret = EZCFG_RET_FAIL;
  int i = 0;
  struct timespec req;
  struct timespec rem;

  ASSERT(process != NULL);

  pthread_mutex_lock(&(process->process_mutex));

  if (process->state == PROCESS_STATE_RUNNING) {
    process->state = PROCESS_STATE_STOPPING;
    if (kill(process->process_id, sig) < 0) {
      EZDBG("%s(%d)\n", __func__, __LINE__);
      pthread_mutex_unlock(&(process->process_mutex));
      return EZCFG_RET_FAIL;
    }
    /* sleep 500 ms */
    req.tv_sec = 0;
    req.tv_nsec = 500000000;
    if (nanosleep(&req, &rem) == -1) {
      EZDBG("%s(%d) errno=[%d]\n", __func__, __LINE__, errno);
      EZDBG("%s(%d) rem.tv_sec=[%ld]\n", __func__, __LINE__, (long)rem.tv_sec);
      EZDBG("%s(%d) rem.tv_nsec=[%ld]\n", __func__, __LINE__, rem.tv_nsec);
    }
  }

  i = 0;
  while (process->state != PROCESS_STATE_STOPPED) {
    if (process->force_stop > 0) {
      if (i == process->force_stop) {
        EZDBG("%s(%d)\n", __func__, __LINE__);
        kill(process->process_id, SIGKILL);
        process->state = PROCESS_STATE_STOPPED;
        pthread_mutex_unlock(&(process->process_mutex));
        return EZCFG_RET_OK;
      }
      i++;
    }
    /* sleep 500 ms */
    req.tv_sec = 0;
    req.tv_nsec = 500000000;
    if (nanosleep(&req, &rem) == -1) {
      EZDBG("%s(%d) errno=[%d]\n", __func__, __LINE__, errno);
      EZDBG("%s(%d) rem.tv_sec=[%ld]\n", __func__, __LINE__, (long)rem.tv_sec);
      EZDBG("%s(%d) rem.tv_nsec=[%ld]\n", __func__, __LINE__, rem.tv_nsec);
    }
    ret = proc_has_no_process(process);
    if (ret == EZCFG_RET_OK) {
      process->state = PROCESS_STATE_STOPPED;
    }
  }

  pthread_mutex_unlock(&(process->process_mutex));
  return EZCFG_RET_OK;
}

int ezcfg_process_proc_has_no_process(struct ezcfg_process *process)
{
  ASSERT(process != NULL);
  return proc_has_no_process(process);
}

int ezcfg_process_state_set_stopped(struct ezcfg_process *process)
{
  ASSERT(process != NULL);
  pthread_mutex_lock(&(process->process_mutex));
  process->state = PROCESS_STATE_STOPPED;
  pthread_mutex_unlock(&(process->process_mutex));
  return EZCFG_RET_OK;
}

int ezcfg_process_state_is_stopped(struct ezcfg_process *process)
{
  int ret = EZCFG_RET_FAIL;
  ASSERT(process != NULL);

  pthread_mutex_lock(&(process->process_mutex));
  if (process->state == PROCESS_STATE_STOPPED) {
    ret = EZCFG_RET_OK;
  }
  else {
    ret = EZCFG_RET_FAIL;
  }
  pthread_mutex_unlock(&(process->process_mutex));

  return ret;
}

int ezcfg_process_del_handler(void *data)
{
  ASSERT(data != NULL);
  return ezcfg_process_del((struct ezcfg_process *)data);
}

int ezcfg_process_cmp_handler(const void *d1, const void *d2)
{
  struct ezcfg_process *p1 = NULL;
  struct ezcfg_process *p2 = NULL;

  ASSERT(d1 != NULL);
  ASSERT(d2 != NULL);

  p1 = (struct ezcfg_process *)d1;
  p2 = (struct ezcfg_process *)d2;

  ASSERT(p1->command != NULL);
  ASSERT(p2->command != NULL);

  if ((p1->process_id == p2->process_id) &&
      (strcmp(p1->command, p2->command) == 0)) {
    return 0;
  }
  else {
    return -1;
  }
}
