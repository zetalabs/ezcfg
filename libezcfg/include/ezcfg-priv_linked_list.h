/* ============================================================================
 * Project Name : ezbox configuration utilities
 * File Name    : ezcfg-priv_linked_list.h
 *
 * Description  : interface to configurate ezbox information
 *
 * Copyright (C) 2008-2014 by ezbox-project
 *
 * History      Rev       Description
 * 2014-03-18   0.1       Split it from ezcfg-priv_common.h
 * ============================================================================
 */

#ifndef _EZCFG_PRIV_LINKED_LIST_H_
#define _EZCFG_PRIV_LINKED_LIST_H_

#include "ezcfg-types.h"


/* list/linked_list.c */
struct ezcfg_linked_list;
struct ezcfg_linked_list *ezcfg_linked_list_new(struct ezcfg *ezcfg);
void ezcfg_linked_list_delete(struct ezcfg_linked_list *list);
bool ezcfg_linked_list_insert(struct ezcfg_linked_list *list, void *data);
bool ezcfg_linked_list_append(struct ezcfg_linked_list *list, void *data);
void *ezcfg_linked_list_take_data(struct ezcfg_linked_list *list);
bool ezcfg_linked_list_remove(struct ezcfg_linked_list *list, void *data);
bool ezcfg_linked_list_in(struct ezcfg_linked_list *list, void *data);
int ezcfg_linked_list_get_length(struct ezcfg_linked_list *list);
void *ezcfg_linked_list_get_node_data_by_index(struct ezcfg_linked_list *list, int i);

#endif /* _EZCFG_PRIV_LINKED_LIST_H_ */
