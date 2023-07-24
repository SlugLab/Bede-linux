#include "bede.h"
#include "linux/compiler_attributes.h"
#include "linux/list.h"
#include "linux/memcontrol.h"
#include "linux/mempolicy.h"
#include "linux/workqueue.h"

struct memory_stat {
	const char *name;
	unsigned int idx;
};

static const struct memory_stat memory_stats[] = {
	{ "anon",			NR_ANON_MAPPED			},
	{ "file",			NR_FILE_PAGES			},
	{ "kernel",			MEMCG_KMEM			},
	{ "kernel_stack",		NR_KERNEL_STACK_KB		},
	{ "pagetables",			NR_PAGETABLE			},
	{ "sec_pagetables",		NR_SECONDARY_PAGETABLE		},
	{ "percpu",			MEMCG_PERCPU_B			},
	{ "sock",			MEMCG_SOCK			},
	{ "vmalloc",			MEMCG_VMALLOC			},
	{ "shmem",			NR_SHMEM			},
#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_ZSWAP)
	{ "zswap",			MEMCG_ZSWAP_B			},
	{ "zswapped",			MEMCG_ZSWAPPED			},
#endif
	{ "file_mapped",		NR_FILE_MAPPED			},
	{ "file_dirty",			NR_FILE_DIRTY			},
	{ "file_writeback",		NR_WRITEBACK			},
#ifdef CONFIG_SWAP
	{ "swapcached",			NR_SWAPCACHE			},
#endif
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	{ "anon_thp",			NR_ANON_THPS			},
	{ "file_thp",			NR_FILE_THPS			},
	{ "shmem_thp",			NR_SHMEM_THPS			},
#endif
	{ "inactive_anon",		NR_INACTIVE_ANON		},
	{ "active_anon",		NR_ACTIVE_ANON			},
	{ "inactive_file",		NR_INACTIVE_FILE		},
	{ "active_file",		NR_ACTIVE_FILE			},
	{ "unevictable",		NR_UNEVICTABLE			},
	{ "slab_reclaimable",		NR_SLAB_RECLAIMABLE_B		},
	{ "slab_unreclaimable",		NR_SLAB_UNRECLAIMABLE_B		},

	/* The memory events */
	{ "workingset_refault_anon",	WORKINGSET_REFAULT_ANON		},
	{ "workingset_refault_file",	WORKINGSET_REFAULT_FILE		},
	{ "workingset_activate_anon",	WORKINGSET_ACTIVATE_ANON	},
	{ "workingset_activate_file",	WORKINGSET_ACTIVATE_FILE	},
	{ "workingset_restore_anon",	WORKINGSET_RESTORE_ANON		},
	{ "workingset_restore_file",	WORKINGSET_RESTORE_FILE		},
	{ "workingset_nodereclaim",	WORKINGSET_NODERECLAIM		},
};
void bede_walk_page_table_and_migrate_to_node(struct task_struct *task,
						int from_node,int to_node, int count)
{
	struct mm_struct *mm;
	struct mem_cgroup *memcg;
	struct lru_gen_mm_list mm_list;
	struct folio src_folio;
	// Get the memory management structure of the task
	mm = get_task_mm(task);
	if (!mm) {
		pr_info("Failed to get mm_struct for pid %d\n", task->pid);
		return;
	}
	memcg = get_mem_cgroup_from_mm(mm);
	if (!memcg) {
		pr_info("Failed to get mem_cgroup for pid %d\n", task->pid);
		return;
	}
	// Your implementation for walking the lru list and calling
	// migrate_misplaced_page
	mm_list = memcg->mm_list;
	// demotion has a hierarchy
	// struct lruvec *lruvec = mem_cgroup_lruvec(memcg, i);
	// struct list_head *head = &lruvec->lists[LRU_ACTIVE];
	// struct list_head *page = head->next;
	// while (page != head) {
	// 	struct page *p = lru_to_page(page);
	// 	if (p->mapping) {
	// 		struct address_space *mapping = p->mapping;
	// 		struct folio *folio = page_folio(p);
	// 		if (folio_migrate_mapping(mapping)) {
	// 			migrate_misplaced_page(folio, node);
	// 		}
	// 	}
	// 	page = page->next;
	// }

	mmput(mm);
}
EXPORT_SYMBOL_GPL(bede_walk_page_table_and_migrate_to_node);

int bede_get_node(struct mem_cgroup *memcg, int node) {
	if (memcg->node_limit[node] > memcg->node_rss[node]) {
		return node;
	}
	for (int i = 0; i < 4; i++) {
		if (memcg->node_limit[i] > memcg->node_rss[i]) {
			return i;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(bede_get_node);

bool bede_is_local_bind(struct mem_cgroup *memcg) {
	if (memcg->node_limit[0] == 0) {
		return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(bede_is_local_bind);

struct bede_work_struct *bede_work_alloc(struct cgroup *cgrp){
	struct bede_work_struct *bede_work;
	bede_work = kzalloc(sizeof(*bede_work), GFP_KERNEL);
	if (!bede_work)
		return NULL;
	bede_work->cgrp = cgrp;
	bede_work->workqueue = alloc_workqueue("bede_workqueue", 0, 0);
	if (!bede_work->workqueue) {
		kfree(bede_work);
		return NULL;
	}
	INIT_DELAYED_WORK(&bede_work->work, bede_do_page_walk_and_migration);
	return bede_work;
}
EXPORT_SYMBOL_GPL(bede_work_alloc);
void bede_flush_node_rss(struct mem_cgroup *memcg) { // work around for every time call policy_node for delayed
	int i;
	mem_cgroup_flush_stats();
	for(i = 0; i < 4; i++){
		memcg->node_rss[i] = 0;
	}
	int nid;
	for_each_node_state(nid, N_MEMORY) {
		u64 size;
		struct lruvec *lruvec;
		
		lruvec = mem_cgroup_lruvec(memcg, NODE_DATA(nid));
		size = lruvec_page_state(lruvec, NR_PAGETABLE) * PAGE_SIZE;
		memcg->node_rss[nid] += size >> 21;
		
	}
}
EXPORT_SYMBOL_GPL(bede_flush_node_rss);

void bede_do_page_walk_and_migration(struct work_struct *work) 
{
	struct bede_work_struct *bede_work = container_of(work, struct bede_work_struct, work.work);
	struct mem_cgroup *memcg;
        struct task_struct *task;
        struct cgroup_pidlist *l, *tmp_l;
        mutex_lock(&bede_work->cgrp->pidlist_mutex);
        int index = 0, pid = 1,res;

        list_for_each_entry_safe(l, tmp_l, &bede_work->cgrp->pidlists, links) {
                int end = l->length;

                while (index < end) {
                  pid = l->list[index];
                  if (pid) {
                    rcu_read_lock();
                    task = pid_task(find_vpid(pid), PIDTYPE_PID);
                    rcu_read_unlock();

                    // scan the whole list of cgrp for getting the
                    // migration task.
                    if (!task) {
                      pr_info("Task not found for pid %d\n", pid);
                      return;
                    }
		    memcg = get_mem_cgroup_from_mm(task->mm);
		    bede_flush_node_rss(memcg);
                    res = bede_get_node(memcg, 0);
		    // Here consider the control of node limit vs. node rss
                    if (bede_work->should_migrate){ // The same as before requires it's filled to full
			if (res) {  // denote
                      		bede_walk_page_table_and_migrate_to_node(task, 0, res, memcg->node_rss[res]-memcg->node_limit[res]);
                    	} else { // promote
				bede_walk_page_table_and_migrate_to_node(task, res, 0, memcg->node_limit[res]-memcg->node_rss[res]);
		    	}
		    }
                  }
                  index++;
                }
        }
        mutex_unlock(&bede_work->cgrp->pidlist_mutex);
}

void bede_append_page_walk_and_migration(struct bede_work_struct *bede_work)
{
        // Re-queue the work with a delay
        queue_delayed_work(bede_work->workqueue, &bede_work->work,
                           msecs_to_jiffies(0));
        flush_workqueue(bede_work->workqueue);
}
EXPORT_SYMBOL_GPL(bede_append_page_walk_and_migration);