#include "bede.h"
#include "linux/compiler_attributes.h"
#include "linux/list.h"
#include "linux/memcontrol.h"
#include "linux/mempolicy.h"
#include "linux/workqueue.h"
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/pagewalk.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/hugetlb.h>
#include <linux/huge_mm.h>
#include <linux/rmap.h>
#include <linux/ksm.h>

/* Global watermark configuration */
struct bede_watermark bede_watermarks = {
	.high_watermark = 80,    /* Default 80% memory usage triggers demotion */
	.low_watermark = 20,     /* Default 20% memory usage triggers promotion */
	.migration_limit = 1024  /* Default migrate 1024 pages per cycle */
};
EXPORT_SYMBOL_GPL(bede_watermarks);

/* Workqueue for promotion and demotion tasks */
static struct workqueue_struct *bede_promotion_wq;
static struct workqueue_struct *bede_demotion_wq;
static struct delayed_work bede_promotion_work;
static struct delayed_work bede_demotion_work;

bool bede_flush_node_rss(struct mem_cgroup *memcg) { // work around for every time call policy_node for delayed
	int nid;
	if (mem_cgroup_disabled()){
		return false;
	}
	mem_cgroup_flush_stats();
	for_each_node_state(nid, N_MEMORY) {
		u64 size;
		struct lruvec *lruvec;
		pg_data_t *pgdat = NODE_DATA(nid);
		if (!pgdat)
			return false;
		lruvec = mem_cgroup_lruvec(memcg, pgdat);
		if (!lruvec)
			return false;
		size = lruvec_page_state_local(lruvec, NR_ANON_MAPPED) >> PAGE_SHIFT;
		memcg->node_rss[nid] = size >> 20;
	}
	return true;
}
EXPORT_SYMBOL_GPL(bede_flush_node_rss);

/* Context structure for page table walk */
struct bede_migrate_ctx {
	int from_node;
	int to_node;
	int pages_to_migrate;
	int pages_migrated;
	struct list_head *page_list;
};

/* Handle transparent huge pages */
static int bede_pmd_entry(pmd_t *pmd, unsigned long addr,
			  unsigned long next, struct mm_walk *walk)
{
	struct bede_migrate_ctx *ctx = walk->private;
	struct vm_area_struct *vma = walk->vma;
	struct page *page;
	int nid;
	
	if (!pmd_present(*pmd) || !pmd_trans_huge(*pmd))
		return 0;
		
	page = pmd_page(*pmd);
	if (!page)
		return 0;
		
	/* Check if we've already migrated enough pages */
	if (ctx->pages_migrated >= ctx->pages_to_migrate)
		return 1; /* Stop walking */
		
	/* Get the node ID of the page */
	nid = page_to_nid(page);
	
	/* Only migrate pages from the source node */
	if (nid != ctx->from_node)
		return 0;
		
	/* For THP, count it as multiple pages */
	if (ctx->pages_migrated + HPAGE_PMD_NR > ctx->pages_to_migrate)
		return 0; /* Skip if it would exceed limit */
		
	/* Try to isolate the THP for migration */
	if (isolate_lru_page(page) != 0)
		return 0;
		
	/* Add page to migration list */
	list_add_tail(&page->lru, ctx->page_list);
	ctx->pages_migrated += HPAGE_PMD_NR;
	
	return 0;
}

/* Page table entry handler for migration */
static int bede_pte_entry(pte_t *pte, unsigned long addr,
			  unsigned long next, struct mm_walk *walk)
{
	struct bede_migrate_ctx *ctx = walk->private;
	struct vm_area_struct *vma = walk->vma;
	struct page *page;
	int nid;
	
	if (!pte_present(*pte))
		return 0;
		
	page = vm_normal_page(vma, addr, *pte);
	if (!page || !page_mapped(page))
		return 0;
		
	/* Check if we've already migrated enough pages */
	if (ctx->pages_migrated >= ctx->pages_to_migrate)
		return 1; /* Stop walking */
		
	/* Get the node ID of the page */
	nid = page_to_nid(page);
	
	/* Only migrate pages from the source node */
	if (nid != ctx->from_node)
		return 0;
		
	/* Check if page is migratable */
	if (PageKsm(page) || PageHuge(page))
		return 0;
		
	/* Skip if page is part of a compound page that was already handled */
	if (PageCompound(page) && !PageHead(page))
		return 0;
		
	/* Try to isolate the page for migration */
	if (isolate_lru_page(page) != 0)
		return 0;
		
	/* Add page to migration list */
	list_add_tail(&page->lru, ctx->page_list);
	ctx->pages_migrated++;
	
	return 0;
}

static const struct mm_walk_ops bede_walk_ops = {
	.pmd_entry = bede_pmd_entry,
	.pte_entry = bede_pte_entry,
};

void bede_walk_page_table_and_migrate_to_node(struct task_struct *task,
						int from_node, int to_node, int count)
{
	struct mm_struct *mm;
	struct mem_cgroup *memcg;
	struct bede_migrate_ctx ctx;
	struct vm_area_struct *vma;
	LIST_HEAD(page_list);
	int err;
	
	pr_debug("bede: Migrating %d pages from node %d to node %d for pid %d\n",
		 count, from_node, to_node, task->pid);
	
	/* Get the memory management structure of the task */
	mm = get_task_mm(task);
	if (!mm) {
		pr_info("bede: Failed to get mm_struct for pid %d\n", task->pid);
		return;
	}
	
	memcg = get_mem_cgroup_from_mm(mm);
	if (!memcg) {
		pr_info("bede: Failed to get mem_cgroup for pid %d\n", task->pid);
		mmput(mm);
		return;
	}
	
	/* Initialize migration context */
	ctx.from_node = from_node;
	ctx.to_node = to_node;
	ctx.pages_to_migrate = count;
	ctx.pages_migrated = 0;
	ctx.page_list = &page_list;
	
	/* Walk through VMAs and collect pages to migrate */
	mmap_read_lock(mm);
	for (vma = mm->mmap; vma && ctx.pages_migrated < count; vma = vma->vm_next) {
		/* Skip special VMAs */
		if (vma->vm_flags & (VM_HUGETLB | VM_PFNMAP | VM_MIXEDMAP))
			continue;
			
		/* Walk the page tables for this VMA */
		err = walk_page_range(mm, vma->vm_start, vma->vm_end,
				      &bede_walk_ops, &ctx);
		if (err)
			break;
	}
	mmap_read_unlock(mm);
	
	/* Migrate the collected pages */
	if (!list_empty(&page_list)) {
		struct migration_target_control mtc = {
			.nid = to_node,
			.gfp_mask = GFP_HIGHUSER_MOVABLE,
		};
		
		pr_info("bede: Migrating %d pages from node %d to node %d\n",
			ctx.pages_migrated, from_node, to_node);
		
		/* Perform the actual migration */
		err = migrate_pages(&page_list, alloc_migration_target, NULL,
				    (unsigned long)&mtc, MIGRATE_SYNC,
				    MR_NUMA_MISPLACED, NULL);
		
		if (err)
			pr_warn("bede: Migration failed with error %d\n", err);
		else
			pr_info("bede: Successfully migrated %d pages\n",
				ctx.pages_migrated);
		
		/* Release any pages that failed to migrate */
		if (!list_empty(&page_list))
			putback_movable_pages(&page_list);
	}
	
	css_put(&memcg->css);
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

void bede_do_page_walk_and_migration(struct work_struct *work) 
{
	struct bede_work_struct *bede_work = container_of(work, struct bede_work_struct, work.work);
	struct mem_cgroup *memcg;
	struct task_struct *task;
	struct cgroup_pidlist *l, *tmp_l;
	int index, pid, target_node;
	int pages_to_migrate;
	
	pr_debug("bede: Starting page walk and migration work\n");
	
	mutex_lock(&bede_work->cgrp->pidlist_mutex);
	
	list_for_each_entry_safe(l, tmp_l, &bede_work->cgrp->pidlists, links) {
		int end = l->length;
		index = 0;
		
		while (index < end) {
			pid = l->list[index];
			if (pid) {
				rcu_read_lock();
				task = pid_task(find_vpid(pid), PIDTYPE_PID);
				if (task && task->mm) {
					get_task_struct(task);
					rcu_read_unlock();
					
					/* Get memory cgroup for this task */
					memcg = get_mem_cgroup_from_mm(task->mm);
					if (memcg) {
						/* Flush node RSS to get current stats */
						bede_flush_node_rss(memcg);
						
						/* Check if migration is needed */
						if (bede_work->should_migrate) {
							int node;
							
							/* Check each node for migration needs */
							for (node = 0; node < MAX_NUMNODES; node++) {
								/* Skip nodes with no limit set */
								if (memcg->node_limit[node] == 0)
									continue;
								
								/* Check if node is over limit */
								if (memcg->node_rss[node] > memcg->node_limit[node]) {
									/* Find target node with available space */
									target_node = bede_get_node(memcg, node);
									if (target_node != node) {
										/* Calculate pages to migrate */
										pages_to_migrate = memcg->node_rss[node] - 
												   memcg->node_limit[node];
										
										pr_info("bede: Node %d over limit, migrating %d pages to node %d\n",
											node, pages_to_migrate, target_node);
										
										/* Perform migration (demotion) */
										bede_walk_page_table_and_migrate_to_node(task, 
											node, target_node, pages_to_migrate);
									}
								}
								/* Check if node is under-utilized (promotion opportunity) */
								else if (memcg->node_rss[node] < (memcg->node_limit[node] / 2)) {
									/* For fast nodes (e.g., node 0), try to promote pages */
									if (node == 0) {
										int slow_node;
										for (slow_node = 1; slow_node < MAX_NUMNODES; slow_node++) {
											if (memcg->node_rss[slow_node] > 0) {
												pages_to_migrate = min(
													(memcg->node_limit[node] - memcg->node_rss[node]) / 2,
													memcg->node_rss[slow_node] / 4
												);
												
												if (pages_to_migrate > 0) {
													pr_info("bede: Node %d under-utilized, promoting %d pages from node %d\n",
														node, pages_to_migrate, slow_node);
													
													/* Perform migration (promotion) */
													bede_walk_page_table_and_migrate_to_node(task,
														slow_node, node, pages_to_migrate);
													break;
												}
											}
										}
									}
								}
							}
						}
						
						css_put(&memcg->css);
					}
					
					put_task_struct(task);
				} else {
					rcu_read_unlock();
				}
			}
			index++;
		}
	}
	
	mutex_unlock(&bede_work->cgrp->pidlist_mutex);
	
	/* Re-queue work if continuous migration is enabled */
	if (bede_work->should_migrate) {
		queue_delayed_work(bede_work->workqueue, &bede_work->work,
				   msecs_to_jiffies(5000)); /* Check again in 5 seconds */
	}
}

void bede_append_page_walk_and_migration(struct bede_work_struct *bede_work)
{
        // Re-queue the work with a delay
        queue_delayed_work(bede_work->workqueue, &bede_work->work,
                           msecs_to_jiffies(0));
        flush_workqueue(bede_work->workqueue);
}
EXPORT_SYMBOL_GPL(bede_append_page_walk_and_migration);

/* Check if promotion is needed based on watermarks */
static bool should_promote(struct mem_cgroup *memcg, int node)
{
	unsigned long node_usage_percent;
	
	if (!memcg || node < 0 || node >= MAX_NUMNODES)
		return false;
	
	/* Calculate node memory usage percentage */
	if (memcg->node_limit[node] == 0)
		return false;
		
	node_usage_percent = (memcg->node_rss[node] * 100) / memcg->node_limit[node];
	
	return node_usage_percent < bede_watermarks.low_watermark;
}

/* Check if demotion is needed based on watermarks */
static bool should_demote(struct mem_cgroup *memcg, int node)
{
	unsigned long node_usage_percent;
	
	if (!memcg || node < 0 || node >= MAX_NUMNODES)
		return false;
	
	/* Calculate node memory usage percentage */
	if (memcg->node_limit[node] == 0)
		return false;
		
	node_usage_percent = (memcg->node_rss[node] * 100) / memcg->node_limit[node];
	
	return node_usage_percent > bede_watermarks.high_watermark;
}

/* Promotion work function - moves pages from slow to fast memory */
void bede_promotion(struct work_struct *work)
{
	struct cgroup_subsys_state *css;
	struct mem_cgroup *memcg;
	int fast_node = 0;  /* Assuming node 0 is fast memory */
	int slow_node, pages_to_migrate;
	
	pr_debug("bede_promotion: Starting promotion cycle\n");
	
	/* Iterate through all memory cgroups */
	rcu_read_lock();
	css_for_each_descendant_pre(css, &root_mem_cgroup->css) {
		memcg = mem_cgroup_from_css(css);
		if (!memcg || !css_tryget(css))
			continue;
			
		/* Flush node RSS to get current stats */
		bede_flush_node_rss(memcg);
		
		/* Check if fast node needs more pages (below low watermark) */
		if (should_promote(memcg, fast_node)) {
			/* Find a slow node with available pages */
			for (slow_node = 1; slow_node < MAX_NUMNODES; slow_node++) {
				if (memcg->node_rss[slow_node] > 0) {
					/* Calculate pages to migrate (limited by watermark) */
					pages_to_migrate = min(
						(unsigned long)bede_watermarks.migration_limit,
						memcg->node_rss[slow_node]
					);
					
					pr_info("bede_promotion: Promoting %d pages from node %d to node %d for memcg\n",
						pages_to_migrate, slow_node, fast_node);
					
					/* Use existing migration infrastructure */
					struct task_struct *task;
					struct cgroup_pidlist *l;
					
					/* Find a task in this memcg to migrate pages */
					mutex_lock(&memcg->css.cgroup->pidlist_mutex);
					list_for_each_entry(l, &memcg->css.cgroup->pidlists, links) {
						if (l->length > 0 && l->list[0]) {
							rcu_read_lock();
							task = pid_task(find_vpid(l->list[0]), PIDTYPE_PID);
							if (task) {
								bede_walk_page_table_and_migrate_to_node(task, 
									slow_node, fast_node, pages_to_migrate);
							}
							rcu_read_unlock();
							break;
						}
					}
					mutex_unlock(&memcg->css.cgroup->pidlist_mutex);
					break;
				}
			}
		}
		
		css_put(css);
	}
	rcu_read_unlock();
	
	/* Re-queue the work for periodic execution */
	queue_delayed_work(bede_promotion_wq, &bede_promotion_work,
			   msecs_to_jiffies(5000)); /* Check every 5 seconds */
}
EXPORT_SYMBOL_GPL(bede_promotion);

/* Demotion work function - moves pages from fast to slow memory */
void bede_demotion(struct work_struct *work)
{
	struct cgroup_subsys_state *css;
	struct mem_cgroup *memcg;
	int fast_node = 0;  /* Assuming node 0 is fast memory */
	int slow_node, pages_to_migrate;
	
	pr_debug("bede_demotion: Starting demotion cycle\n");
	
	/* Iterate through all memory cgroups */
	rcu_read_lock();
	css_for_each_descendant_pre(css, &root_mem_cgroup->css) {
		memcg = mem_cgroup_from_css(css);
		if (!memcg || !css_tryget(css))
			continue;
			
		/* Flush node RSS to get current stats */
		bede_flush_node_rss(memcg);
		
		/* Check if fast node is over high watermark */
		if (should_demote(memcg, fast_node)) {
			/* Find a slow node with available capacity */
			for (slow_node = 1; slow_node < MAX_NUMNODES; slow_node++) {
				if (memcg->node_limit[slow_node] > memcg->node_rss[slow_node]) {
					/* Calculate pages to migrate (limited by watermark) */
					unsigned long space_available = 
						memcg->node_limit[slow_node] - memcg->node_rss[slow_node];
					pages_to_migrate = min(
						bede_watermarks.migration_limit,
						space_available
					);
					
					pr_info("bede_demotion: Demoting %ld pages from node %d to node %d for memcg\n",
						pages_to_migrate, fast_node, slow_node);
					
					/* Use existing migration infrastructure */
					struct task_struct *task;
					struct cgroup_pidlist *l;
					
					/* Find a task in this memcg to migrate pages */
					mutex_lock(&memcg->css.cgroup->pidlist_mutex);
					list_for_each_entry(l, &memcg->css.cgroup->pidlists, links) {
						if (l->length > 0 && l->list[0]) {
							rcu_read_lock();
							task = pid_task(find_vpid(l->list[0]), PIDTYPE_PID);
							if (task) {
								bede_walk_page_table_and_migrate_to_node(task, 
									fast_node, slow_node, pages_to_migrate);
							}
							rcu_read_unlock();
							break;
						}
					}
					mutex_unlock(&memcg->css.cgroup->pidlist_mutex);
					break;
				}
			}
		}
		
		css_put(css);
	}
	rcu_read_unlock();
	
	/* Re-queue the work for periodic execution */
	queue_delayed_work(bede_demotion_wq, &bede_demotion_work,
			   msecs_to_jiffies(5000)); /* Check every 5 seconds */
}
EXPORT_SYMBOL_GPL(bede_demotion);

/* Initialize the bede kthread and workqueues */
int bede_init_kthread(void)
{
	int ret;
	
	pr_info("bede: Initializing bede kthread and workqueues\n");
	
	/* Initialize sysfs interface first */
	ret = bede_sysfs_init();
	if (ret) {
		pr_err("bede: Failed to initialize sysfs interface\n");
		return ret;
	}
	
	/* Create dedicated workqueues for promotion and demotion */
	bede_promotion_wq = alloc_workqueue("bede_promotion", 
					    WQ_MEM_RECLAIM | WQ_CPU_INTENSIVE, 1);
	if (!bede_promotion_wq) {
		pr_err("bede: Failed to create promotion workqueue\n");
		bede_sysfs_exit();
		return -ENOMEM;
	}
	
	bede_demotion_wq = alloc_workqueue("bede_demotion",
					   WQ_MEM_RECLAIM | WQ_CPU_INTENSIVE, 1);
	if (!bede_demotion_wq) {
		pr_err("bede: Failed to create demotion workqueue\n");
		destroy_workqueue(bede_promotion_wq);
		bede_sysfs_exit();
		return -ENOMEM;
	}
	
	/* Initialize delayed work structures */
	INIT_DELAYED_WORK(&bede_promotion_work, bede_promotion);
	INIT_DELAYED_WORK(&bede_demotion_work, bede_demotion);
	
	/* Queue initial work */
	queue_delayed_work(bede_promotion_wq, &bede_promotion_work,
			   msecs_to_jiffies(10000)); /* Start after 10 seconds */
	queue_delayed_work(bede_demotion_wq, &bede_demotion_work,
			   msecs_to_jiffies(10000)); /* Start after 10 seconds */
	
	pr_info("bede: Kthread and workqueues initialized successfully\n");
	pr_info("bede: Watermark control available at /sys/kernel/bede/\n");
	return 0;
}
EXPORT_SYMBOL_GPL(bede_init_kthread);

/* Set watermarks from userspace */
void bede_set_watermarks(unsigned long high, unsigned long low, unsigned long limit)
{
	if (high > 100 || low > 100 || high <= low) {
		pr_err("bede: Invalid watermark values (high=%lu, low=%lu)\n", high, low);
		return;
	}
	
	bede_watermarks.high_watermark = high;
	bede_watermarks.low_watermark = low;
	bede_watermarks.migration_limit = limit;
	
	pr_info("bede: Updated watermarks - high=%lu%%, low=%lu%%, limit=%lu pages\n",
		high, low, limit);
}
EXPORT_SYMBOL_GPL(bede_set_watermarks);

/* Sysfs attributes for watermark control */
static ssize_t high_watermark_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", bede_watermarks.high_watermark);
}

static ssize_t high_watermark_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	unsigned long val;
	int ret;

	ret = kstrtoul(buf, 10, &val);
	if (ret < 0)
		return ret;

	if (val > 100 || val <= bede_watermarks.low_watermark)
		return -EINVAL;

	bede_watermarks.high_watermark = val;
	return count;
}

static ssize_t low_watermark_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", bede_watermarks.low_watermark);
}

static ssize_t low_watermark_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	unsigned long val;
	int ret;

	ret = kstrtoul(buf, 10, &val);
	if (ret < 0)
		return ret;

	if (val > 100 || val >= bede_watermarks.high_watermark)
		return -EINVAL;

	bede_watermarks.low_watermark = val;
	return count;
}

static ssize_t migration_limit_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", bede_watermarks.migration_limit);
}

static ssize_t migration_limit_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	unsigned long val;
	int ret;

	ret = kstrtoul(buf, 10, &val);
	if (ret < 0)
		return ret;

	if (val == 0)
		return -EINVAL;

	bede_watermarks.migration_limit = val;
	return count;
}

static struct kobj_attribute high_watermark_attr =
	__ATTR(high_watermark, 0644, high_watermark_show, high_watermark_store);
static struct kobj_attribute low_watermark_attr =
	__ATTR(low_watermark, 0644, low_watermark_show, low_watermark_store);
static struct kobj_attribute migration_limit_attr =
	__ATTR(migration_limit, 0644, migration_limit_show, migration_limit_store);

static struct attribute *bede_attrs[] = {
	&high_watermark_attr.attr,
	&low_watermark_attr.attr,
	&migration_limit_attr.attr,
	NULL,
};

static struct attribute_group bede_attr_group = {
	.attrs = bede_attrs,
};

static struct kobject *bede_kobj;

/* Initialize sysfs interface */
static int __init bede_sysfs_init(void)
{
	int ret;

	bede_kobj = kobject_create_and_add("bede", kernel_kobj);
	if (!bede_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(bede_kobj, &bede_attr_group);
	if (ret) {
		kobject_put(bede_kobj);
		return ret;
	}

	pr_info("bede: Sysfs interface created at /sys/kernel/bede/\n");
	return 0;
}

/* Cleanup sysfs interface */
static void bede_sysfs_exit(void)
{
	if (bede_kobj) {
		sysfs_remove_group(bede_kobj, &bede_attr_group);
		kobject_put(bede_kobj);
	}
}

/* Cleanup bede workqueues and resources */
void bede_exit_kthread(void)
{
	pr_info("bede: Cleaning up workqueues and resources\n");
	
	/* Cancel pending work */
	if (bede_promotion_wq) {
		cancel_delayed_work_sync(&bede_promotion_work);
		destroy_workqueue(bede_promotion_wq);
		bede_promotion_wq = NULL;
	}
	
	if (bede_demotion_wq) {
		cancel_delayed_work_sync(&bede_demotion_work);
		destroy_workqueue(bede_demotion_wq);
		bede_demotion_wq = NULL;
	}
	
	/* Cleanup sysfs */
	bede_sysfs_exit();
	
	pr_info("bede: Cleanup complete\n");
}
EXPORT_SYMBOL_GPL(bede_exit_kthread);

/* Module initialization - can be called from mm subsystem init */
static int __init bede_module_init(void)
{
	pr_info("bede: Memory migration module initializing\n");
	return bede_init_kthread();
}

/* Module cleanup */
static void __exit bede_module_exit(void)
{
	pr_info("bede: Memory migration module exiting\n");
	bede_exit_kthread();
}

module_init(bede_module_init);
module_exit(bede_module_exit);

MODULE_DESCRIPTION("BEDE memory migration with promotion/demotion support");
MODULE_AUTHOR("BEDE Team");
MODULE_LICENSE("GPL");

