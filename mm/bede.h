//* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/backend.h
 *
 * Common interface definitions for making balloon pages movable by compaction.
 *
 * Copyright (C) 2023, UCSC Yiwei Yang <yangyiwei2000@gmail.com>
 */

#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/migrate.h>

#include <linux/sched/mm.h>

struct pid_work_struct {
	struct delayed_work work;
	pid_t pid;
};

static struct workqueue_struct *pid_workqueue;
EXPORT_SYMBOL_GPL(pid_workqueue);

static void do_page_walk_and_migration(struct work_struct *work);

