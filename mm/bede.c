#include "bede.h"
#include "linux/list.h"

static void walk_page_table_and_migrate_to_node(struct task_struct *task,
						int node)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long start_addr, end_addr;
	unsigned long address;

	// Get the memory management structure of the task
	mm = get_task_mm(task);
	if (!mm) {
		pr_info("Failed to get mm_struct for pid %d\n", task->pid);
		return;
	}

	// Iterate through virtual memory areas (VMAs)
	down_read(&mm->mmap_lock);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		start_addr = vma->vm_start;
		end_addr = vma->vm_end;

		// Iterate through the pages within the VMA
		for (address = start_addr; address < end_addr;
		     address += PAGE_SIZE) {
			struct page *page;
			spinlock_t *ptl;
			pte_t *pte;

			// Get the PTE for the virtual address
			pte = get_locked_pte(mm, address, &ptl);
			if (!pte) {
				continue;
			}

			// Get the struct page for the PTE
			page = vm_normal_page(vma, address, *pte);
			if (!page) {
				pte_unmap_unlock(pte, ptl);
				continue;
			}

			// Call migrate_misplaced_page if necessary
			if (page_to_nid(page) != node) {
				migrate_misplaced_page(page, vma, node);
			}

			pte_unmap_unlock(pte, ptl);
		}
	}
	up_read(&mm->mmap_lock);
	mmput(mm);
}

static void do_page_walk_and_migration(struct bede_work_struct *bede_work)
{
	int res = 0;
	struct task_struct *task;
	struct list_head pid_list = bede_work->cgrp->pidlists;
	struct cgroup_pidlist *member;
list_for_each_entry(0, pid_list, member){
	rcu_read_lock();
	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	rcu_read_unlock();

	// scan the whole list of cgrp for getting the migration task.

	if (!task) {
                pr_info("Task not found for pid %d\n", bede_work->pid);
                        return;
        }

        // Your implementation for walking the page table and calling
        // migrate_misplaced_page
        if (res) {
                walk_page_table_and_migrate_to_node(task, res);
        }
        // Re-queue the work with a delay
        queue_delayed_work(
            bede_work->workqueue, &bede_work->work,
            msecs_to_jiffies(1000)); // Execute after a delay (e.g., 1000 ms)
}
}