//* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/bede.h
 *
 * Common interface definitions for making balloon pages movable by compaction.
 *
 * Copyright (C) 2023, UCSC Yiwei Yang <yangyiwei2000@gmail.com>
 */

#include <linux/cgroup-defs.h>
#include <linux/cgroup.h>
#include <linux/memcontrol.h>
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
	bool should_migrate;
};
// while true migrate pages?
void bede_walk_page_table_and_migrate_to_node(struct task_struct *task,
						int from_node,int to_node, int count);
void bede_do_page_walk_and_migration(struct work_struct *work);
void bede_append_page_walk_and_migration(struct bede_work_struct *work);
int bede_get_node(struct mem_cgroup *memcg, int node);
bool bede_is_local_bind(struct mem_cgroup *memcg);
struct bede_work_struct *bede_work_alloc(struct cgroup *cgrp);
bool bede_flush_node_rss(struct mem_cgroup *memcg);
