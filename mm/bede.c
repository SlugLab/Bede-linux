#include "bede.h"
#include "internal.h"
#include "linux/compiler_attributes.h"
#include "linux/list.h"
#include "linux/memcontrol.h"
#include "linux/mempolicy.h"
#include "linux/workqueue.h"
#include "linux/mm_inline.h"

extern struct folio *alloc_misplaced_dst_folio(struct folio *src,
					   unsigned long data);
bool bede_flush_node_rss(struct mem_cgroup *memcg) { // work around for every time call policy_node for delayed
	int nid;
	mem_cgroup_flush_stats();
	for_each_node_state(nid, N_MEMORY) {
		u64 size;
		struct lruvec *lruvec;
		pg_data_t *pgdat = NODE_DATA(nid);
		if (!pgdat)
			return true;
		lruvec = mem_cgroup_lruvec(memcg, pgdat);
		if (!lruvec)
			return true;
		size = (lruvec_page_state(lruvec, NR_ANON_MAPPED)+lruvec_page_state(lruvec, NR_FILE_PAGES)) << PAGE_SHIFT;
		memcg->node_rss[nid] = size >> 20;
	}
	return true;
}
EXPORT_SYMBOL_GPL(bede_flush_node_rss);

void bede_walk_page_table_and_migrate_to_node(struct task_struct *task,
						int from_node,int to_node, int count)
{
	struct mm_struct *mm;
	struct mem_cgroup *memcg;
	struct lru_gen_mm_list mm_list;
	int isolated, nr_succeeded = 0, nr_remaining;
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
	pg_data_t *pgdat = NODE_DATA(from_node);
	struct lruvec *lruvec = mem_cgroup_lruvec(memcg, from_node);
	struct list_head *head = &lruvec->lists[LRU_ACTIVE];
	struct list_head *page = head->next;
	while (page != head && count > 0) {
		LIST_HEAD(migratepages);
		struct page *p = lru_to_page(page);
		if (p->mapping) {
			struct address_space *mapping = p->mapping;
			struct folio *folio = page_folio(p);
			// if (folio_migrate_mapping(mapping)) {
			// migrate_misplaced_page(folio, node);
			// }
			list_add(&p->lru, &migratepages);
			nr_remaining = migrate_pages(&migratepages, alloc_misplaced_dst_folio,
						NULL, to_node, MIGRATE_ASYNC,
						MR_NUMA_MISPLACED, &nr_succeeded);
			if (nr_remaining) {
				if (!list_empty(&migratepages)) {
					list_del(&p->lru);
					mod_node_page_state(page_pgdat(p), NR_ISOLATED_ANON +
							page_is_file_lru(p), -thp_nr_pages(p));
					putback_lru_page(p);
				}
				isolated = 0;
			}
			if (nr_succeeded) {
				count_vm_numa_events(NUMA_PAGE_MIGRATE, nr_succeeded);
				mod_node_page_state(pgdat,PGPROMOTE_SUCCESS,
							nr_succeeded);
			}
			BUG_ON(!list_empty(&migratepages));
		}
		page = page->next;
	}

	mmput(mm);
}
EXPORT_SYMBOL_GPL(bede_walk_page_table_and_migrate_to_node);


inline int bede_get_node(struct mem_cgroup *memcg, int node) {
	if (memcg->node_limit[0] > memcg->node_rss[0]) {
		return 0;
	}
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
                //     res = bede_get_node(memcg, 0);
		//     // Here consider the control of node limit vs. node rss
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