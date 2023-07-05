//* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/bede.h
 *
 * Common interface definitions for making balloon pages movable by compaction.
 *
 * Copyright (C) 2023, UCSC Yiwei Yang <yangyiwei2000@gmail.com>
 */

#include <asm/io.h>
#include <linux/cgroup-defs.h>
#include <linux/cgroup.h>
#include <linux/migrate.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/workqueue.h>

#define START_TIME(ts) ts = rdtsc()
#define END_TIME(msg, ts) trace_printk("%s: %llu\n", msg, rdtsc() - ts)

/** Get the cgroup by this struct. */
struct bede_work_struct {
	struct delayed_work work;
	struct workqueue_struct *workqueue;
	// cgroup struct reverse mapping
	struct cgroup *cgrp;
};
// while true migrate pages?
void bede_walk_page_table_and_migrate_to_node(struct task_struct *task,
						int node);
static void bede_do_page_walk_and_migration(struct work_struct *work);
void bede_append_page_walk_and_migration(struct bede_work_struct *work);
int bede_get_node(void);
struct bede_work_struct *bede_work_alloc(struct cgroup *cgrp);