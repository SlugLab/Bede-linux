#include "bede.h"

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
int get_watermark()
{
	return 0;
}
EXPORT_SYMBOL_GPL(get_watermark);
ALLOW_FAULT_INJECTION(get_watermark, TRUE);

static void do_page_walk_and_migration(struct work_struct *work)
{
	struct pid_work_struct *pid_work =
		container_of(work, struct pid_work_struct, work.work);
	int res = 0;
	struct task_struct *task;

	rcu_read_lock();
	task = pid_task(find_vpid(pid_work->pid), PIDTYPE_PID);
	rcu_read_unlock();

	if (!task) {
		pr_info("Task not found for pid %d\n", pid_work->pid);
		return;
	}

	// Your implementation for walking the page table and calling migrate_misplaced_page
	res = get_watermark();
	if (res) {
		walk_page_table_and_migrate_to_node(task, res);
	}
	// Re-queue the work with a delay
	queue_delayed_work(
		my_wq, &pid_work->work,
		msecs_to_jiffies(
			1000)); // Execute after a delay (e.g., 1000 ms)
}