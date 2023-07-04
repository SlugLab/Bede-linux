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
/** Get the cgroup by this struct. */
struct bede_work_struct {
	struct delayed_work work;
	struct workqueue_struct *workqueue;
	// cgroup struct
	struct cgroup *cgrp;
};
// while true migrate pages?

static void do_page_walk_and_migration(struct bede_work_struct *work);

