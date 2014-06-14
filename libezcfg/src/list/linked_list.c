/* ============================================================================
 * Project Name : ezbox configuration utilities
 * Module Name  : list/linked_list.c
 *
 * Description  : single linked list handler
 *
 * Copyright (C) 2008-2014 by ezbox-project
 *
 * History      Rev       Description
 * 2014-03-18   0.1       Reimplement based on linked_list.c
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
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>
#include <ctype.h>
#include <stdarg.h>

#include "ezcfg.h"
#include "ezcfg-private.h"

struct linked_list_node {
	void *data;
	struct linked_list_node *next;
};

struct ezcfg_linked_list {
	struct ezcfg *ezcfg;
	int length;
	struct linked_list_node *head;
	struct linked_list_node *tail;
	int (*data_delete_handler)(void *data);
	int (*data_compare_handler)(const void *d1, const void *d2);
};

/*
 * private functions
 */
static void linked_list_node_delete(struct ezcfg_linked_list *list, struct linked_list_node *p)
{
	if ((list->data_delete_handler != NULL) &&
	    (p->data != NULL)) {
		list->data_delete_handler(p->data);
	}
	free(p);
}

/*
 * public functions
 */
struct ezcfg_linked_list *ezcfg_linked_list_new(struct ezcfg *ezcfg)
{
	struct ezcfg_linked_list *list;
	ASSERT(ezcfg != NULL);

	list = calloc(1, sizeof(struct ezcfg_linked_list));
	if (list != NULL) {
		list->ezcfg = ezcfg;
	}
	return list;
}

void ezcfg_linked_list_delete(struct ezcfg_linked_list *list)
{
	ASSERT(list != NULL);

	while(list->head != NULL) {
		list->tail = list->head;
		list->head = (list->head)->next;
		linked_list_node_delete(list, list->tail);
	}
	free(list);
}

/*
 * add link node to the head
 * replace the node if the name has been there.
 */
bool ezcfg_linked_list_insert(struct ezcfg_linked_list *list, void *data)
{
	struct linked_list_node *np;

	ASSERT(list != NULL);
	ASSERT(data != NULL);

	if ((list->data_compare_handler == NULL) ||
	    (list->data_delete_handler == NULL)) {
		return false;
	}

	np = list->head;

	/* check if the data has been there */
	while(np != NULL) {
		if (list->data_compare_handler(np->data, data) == 0) {
			list->data_delete_handler(np->data);
			np->data = data;
			return true;
		}
		np = np->next;
	}

	/* no such node in the list */
	np = calloc(1, sizeof(struct linked_list_node));
	if (np == NULL) {
		return false;
	}
	np->data = data;

	/* insert node */
	np->next = list->head;
	list->head = np;
	if (list->tail == NULL) {
		list->tail = np;
	}
	list->length += 1;
	return true;
}

/*
 * add link node to the tail
 * replace the node if the name has been there.
 */
bool ezcfg_linked_list_append(struct ezcfg_linked_list *list, void *data)
{
	struct linked_list_node *np;

	ASSERT(list != NULL);
	ASSERT(data != NULL);

	if ((list->data_compare_handler == NULL) ||
	    (list->data_delete_handler == NULL)) {
		return false;
	}

	np = list->head;

	/* check if the name has been there */
	while(np != NULL) {
		if (list->data_compare_handler(np->data, data) == 0) {
			list->data_delete_handler(np->data);
			np->data = data;
			return true;
		}
		np = np->next;
	}

	/* no such node in the list */
	np = calloc(1, sizeof(struct linked_list_node));
	if (np == NULL) {
		return false;
	}
	np->data = data;

	/* append node */
	if (list->tail == NULL) {
		list->head = np;
		list->tail = np;
	}
	else {
		(list->tail)->next = np;
		list->tail = np;
	}
	list->length += 1;
	return true;
}

/*
 * take the data of head link node
 */
void *ezcfg_linked_list_take_data(struct ezcfg_linked_list *list)
{
	struct linked_list_node *np;
	void *data;

	ASSERT(list != NULL);

	np = list->head;

	if (np == NULL) {
		return NULL;
	}

	list->head = np->next;
	if (list->tail == np) {
		list->tail = NULL;
	}
	data = np->data;
	np->data = NULL;
	linked_list_node_delete(list, np);
	list->length -= 1;

	return data;
}

/*
 * remove link node by name
 */
bool ezcfg_linked_list_remove(struct ezcfg_linked_list *list, void *data)
{
	struct linked_list_node *np, *npp;

	ASSERT(list != NULL);
	ASSERT(data != NULL);

	if ((list->data_compare_handler == NULL) ||
	    (list->data_delete_handler == NULL)) {
		return false;
	}

	np = list->head;

	/* remove the head node */
	if (list->data_compare_handler(np->data, data) == 0) {
		list->head = np->next;
		if (np->next == NULL) {
			list->tail = NULL;
		}
		linked_list_node_delete(list, np);
		list->length -= 1;
		return true;
	}

	npp = np;
	np = np->next;

	/* check if the data has been there */
	while(np != NULL) {
		if (list->data_compare_handler(np->data, data) == 0) {
			npp->next = np->next;
			if (np->next == NULL) {
				list->tail = npp;
			}
			linked_list_node_delete(list, np);
			list->length -= 1;
			return true;
		}
		npp = np;
		np = np->next;
	}

	/* no such node in the list */
	return false;
}

bool ezcfg_linked_list_in(struct ezcfg_linked_list *list, void *data)
{
	struct linked_list_node *np;

	ASSERT(list != NULL);
	ASSERT(data != NULL);

	if (list->data_compare_handler == NULL) {
		return false;
	}

	np = list->head;

	/* check if the name has been there */
	while(np != NULL) {
		if (list->data_compare_handler(np->data, data) == 0) {
			return true;
		}
		np = np->next;
	}

	/* no such node in the list */
	return false;
}

int ezcfg_linked_list_get_length(struct ezcfg_linked_list *list)
{
	ASSERT(list != NULL);
	return list->length;
}

void *ezcfg_linked_list_get_node_data_by_index(struct ezcfg_linked_list *list, int i)
{
	struct linked_list_node *np;

	ASSERT(list != NULL);
	ASSERT((i > 0) && (i <= list->length));

	np = list->head;
	i--;

	while (i > 0) {
		np = np->next;
		i--;
	}

	return np->data;
}
