// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kvm.h>
#include <linux/psp-sev.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "svm_util.h"
#include "kselftest.h"
#include "../lib/kvm_util_internal.h"

#define SEV_POLICY_ES 0b100

#define NR_MIGRATE_TEST_VCPUS 4
#define NR_MIGRATE_TEST_VMS 3
#define NR_LOCK_TESTING_THREADS 3
#define NR_LOCK_TESTING_ITERATIONS 10000

static void sev_ioctl(int vm_fd, int cmd_id, void *data)
{
	struct kvm_sev_cmd cmd = {
		.id = cmd_id,
		.data = (uint64_t)data,
		.sev_fd = open_sev_dev_path_or_exit(),
	};
	int ret;

	ret = ioctl(vm_fd, KVM_MEMORY_ENCRYPT_OP, &cmd);
	TEST_ASSERT((ret == 0 || cmd.error == SEV_RET_SUCCESS),
		    "%d failed: return code: %d, errno: %d, fw error: %d",
		    cmd_id, ret, errno, cmd.error);
}

static struct kvm_vm *sev_vm_create(bool es)
{
	struct kvm_vm *vm;
	struct kvm_sev_launch_start start = { 0 };
	int i;

	vm = vm_create(VM_MODE_DEFAULT, 0, O_RDWR);
	sev_ioctl(vm->fd, es ? KVM_SEV_ES_INIT : KVM_SEV_INIT, NULL);
	for (i = 0; i < NR_MIGRATE_TEST_VCPUS; ++i)
		vm_vcpu_add(vm, i);
	if (es)
		start.policy |= SEV_POLICY_ES;
	sev_ioctl(vm->fd, KVM_SEV_LAUNCH_START, &start);
	if (es)
		sev_ioctl(vm->fd, KVM_SEV_LAUNCH_UPDATE_VMSA, NULL);
	return vm;
}

static struct kvm_vm *__vm_create(void)
{
	struct kvm_vm *vm;
	int i;

	vm = vm_create(VM_MODE_DEFAULT, 0, O_RDWR);
	for (i = 0; i < NR_MIGRATE_TEST_VCPUS; ++i)
		vm_vcpu_add(vm, i);

	return vm;
}

static int __sev_migrate_from(int dst_fd, int src_fd)
{
	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_VM_MOVE_ENC_CONTEXT_FROM,
		.args = { src_fd }
	};

	return ioctl(dst_fd, KVM_ENABLE_CAP, &cap);
}


static void sev_migrate_from(int dst_fd, int src_fd)
{
	int ret;

	ret = __sev_migrate_from(dst_fd, src_fd);
	TEST_ASSERT(!ret, "Migration failed, ret: %d, errno: %d\n", ret, errno);
}

static void test_sev_migrate_from(bool es)
{
	struct kvm_vm *src_vm;
	struct kvm_vm *dst_vms[NR_MIGRATE_TEST_VMS];
	int i;

	src_vm = sev_vm_create(es);
	for (i = 0; i < NR_MIGRATE_TEST_VMS; ++i)
		dst_vms[i] = __vm_create();

	/* Initial migration from the src to the first dst. */
	sev_migrate_from(dst_vms[0]->fd, src_vm->fd);

	for (i = 1; i < NR_MIGRATE_TEST_VMS; i++)
		sev_migrate_from(dst_vms[i]->fd, dst_vms[i - 1]->fd);

	/* Migrate the guest back to the original VM. */
	sev_migrate_from(src_vm->fd, dst_vms[NR_MIGRATE_TEST_VMS - 1]->fd);

	kvm_vm_free(src_vm);
	for (i = 0; i < NR_MIGRATE_TEST_VMS; ++i)
		kvm_vm_free(dst_vms[i]);
}

struct locking_thread_input {
	struct kvm_vm *vm;
	int source_fds[NR_LOCK_TESTING_THREADS];
};

static void *locking_test_thread(void *arg)
{
	int i, j;
	struct locking_thread_input *input = (struct locking_thread_input *)arg;

	for (i = 0; i < NR_LOCK_TESTING_ITERATIONS; ++i) {
		j = i % NR_LOCK_TESTING_THREADS;
		__sev_migrate_from(input->vm->fd, input->source_fds[j]);
	}

	return NULL;
}

static void test_sev_migrate_locking(void)
{
	struct locking_thread_input input[NR_LOCK_TESTING_THREADS];
	pthread_t pt[NR_LOCK_TESTING_THREADS];
	int i;

	for (i = 0; i < NR_LOCK_TESTING_THREADS; ++i) {
		input[i].vm = sev_vm_create(/* es= */ false);
		input[0].source_fds[i] = input[i].vm->fd;
	}
	for (i = 1; i < NR_LOCK_TESTING_THREADS; ++i)
		memcpy(input[i].source_fds, input[0].source_fds,
		       sizeof(input[i].source_fds));

	for (i = 0; i < NR_LOCK_TESTING_THREADS; ++i)
		pthread_create(&pt[i], NULL, locking_test_thread, &input[i]);

	for (i = 0; i < NR_LOCK_TESTING_THREADS; ++i)
		pthread_join(pt[i], NULL);
}

static void test_sev_migrate_parameters(void)
{
	struct kvm_vm *sev_vm, *sev_es_vm, *vm_no_vcpu, *vm_no_sev,
		*sev_es_vm_no_vmsa;
	int ret;

	sev_vm = sev_vm_create(/* es= */ false);
	sev_es_vm = sev_vm_create(/* es= */ true);
	vm_no_vcpu = vm_create(VM_MODE_DEFAULT, 0, O_RDWR);
	vm_no_sev = __vm_create();
	sev_es_vm_no_vmsa = vm_create(VM_MODE_DEFAULT, 0, O_RDWR);
	sev_ioctl(sev_es_vm_no_vmsa->fd, KVM_SEV_ES_INIT, NULL);
	vm_vcpu_add(sev_es_vm_no_vmsa, 1);


	ret = __sev_migrate_from(sev_vm->fd, sev_es_vm->fd);
	TEST_ASSERT(
		ret == -1 && errno == EINVAL,
		"Should not be able migrate to SEV enabled VM. ret: %d, errno: %d\n",
		ret, errno);

	ret = __sev_migrate_from(sev_es_vm->fd, sev_vm->fd);
	TEST_ASSERT(
		ret == -1 && errno == EINVAL,
		"Should not be able migrate to SEV-ES enabled VM. ret: %d, errno: %d\n",
		ret, errno);

	ret = __sev_migrate_from(vm_no_vcpu->fd, sev_es_vm->fd);
	TEST_ASSERT(
		ret == -1 && errno == EINVAL,
		"SEV-ES migrations require same number of vCPUS. ret: %d, errno: %d\n",
		ret, errno);

	ret = __sev_migrate_from(vm_no_vcpu->fd, sev_es_vm_no_vmsa->fd);
	TEST_ASSERT(
		ret == -1 && errno == EINVAL,
		"SEV-ES migrations require UPDATE_VMSA. ret %d, errno: %d\n",
		ret, errno);

	ret = __sev_migrate_from(vm_no_vcpu->fd, vm_no_sev->fd);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "Migrations require SEV enabled. ret %d, errno: %d\n", ret,
		    errno);
}

int main(int argc, char *argv[])
{
	test_sev_migrate_from(/* es= */ false);
	test_sev_migrate_from(/* es= */ true);
	test_sev_migrate_locking();
	test_sev_migrate_parameters();
	return 0;
}
