/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/**
 *  ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : composite/socket_agent/socket_agent_comm_api.h
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2016 by ezbox-project
 *
 * History      Rev       Description
 * 2016-01-10   0.1       Write it from scratch
 * ============================================================================
 */

#ifndef _EZCFG_LOCAL_COMPOSITE_SOCKET_AGENT_SOCKET_AGENT_COMM_API_H_
#define _EZCFG_LOCAL_COMPOSITE_SOCKET_AGENT_SOCKET_AGENT_COMM_API_H_

/* ezcfg communication API NV json name string */
#define N_COMMAND	"command"
#define N_SENDER        "sender"
#define N_RECEIVER      "receiver"

/* ezcfg communication API NV json value string */
#define V_EZCFG_REGISTER_AGENT          "ezcfg_register_agent"
#define V_EZCFG_UNREGISTER_AGENT        "ezcfg_unregister_agent"

#endif /* _EZCFG_LOCAL_COMPOSITE_SOCKET_AGENT_SOCKET_AGENT_COMM_API_H_ */
