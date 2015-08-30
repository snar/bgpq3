#ifndef SX_SLENTRY_H_
#define SX_SLENTRY_H_

#if HAVE_SYS_QUEUE_H
#include <sys/queue.h>
/* OpenBSD-current as of 2015-08-30 does not define STAILQ_ENTRY anymore */
#ifndef STAILQ_ENTRY
#include "sys_queue.h"
#endif
#else
#include "sys_queue.h"
#endif

#if HAVE_SYS_TREE_H
#include <sys/tree.h>
#else
#include "sys_tree.h"
#endif

struct sx_slentry {
	STAILQ_ENTRY(sx_slentry) next;
	char*  text;
};

struct sx_slentry* sx_slentry_new(char* text);

struct sx_tentry {
	RB_ENTRY(sx_tentry) entry;
	char* text;
};

struct sx_tentry* sx_tentry_new(char* text);

#endif
