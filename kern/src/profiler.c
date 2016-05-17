/* Copyright (c) 2015 Google Inc
 * Davide Libenzi <dlibenzi@google.com>
 * See LICENSE for details.
 */

#include <ros/common.h>
#include <ros/mman.h>
#include <sys/types.h>
#include <smp.h>
#include <trap.h>
#include <kthread.h>
#include <env.h>
#include <process.h>
#include <mm.h>
#include <vfs.h>
#include <kmalloc.h>
#include <pmap.h>
#include <kref.h>
#include <atomic.h>
#include <umem.h>
#include <elf.h>
#include <ns.h>
#include <err.h>
#include <core_set.h>
#include <string.h>
#include "profiler.h"

#define PROFILER_MAX_PRG_PATH	256
#define PROFILER_BT_DEPTH 16

#define VBE_MAX_SIZE(t) ((8 * sizeof(t) + 6) / 7)

struct profiler_cpu_context {
	struct block *block;
	int cpu;
	int tracing;
	size_t dropped_data_size;
};

static int profiler_queue_limit = 64 * 1024 * 1024;
static size_t profiler_cpu_buffer_size = 65536;
static qlock_t profiler_mtx = QLOCK_INITIALIZER(profiler_mtx);
static struct kref profiler_kref;
static struct profiler_cpu_context *profiler_percpu_ctx;
static struct queue *profiler_queue;

static inline struct profiler_cpu_context *profiler_get_cpu_ctx(int cpu)
{
	return profiler_percpu_ctx + cpu;
}

static inline char *vb_encode_uint64(char *data, uint64_t n)
{
	/* Classical variable bytes encoding. Encodes 7 bits at a time, using bit
	 * number 7 in the byte, as indicator of end of sequence (when zero).
	 */
	for (; n >= 0x80; n >>= 7)
		*data++ = (char) (n | 0x80);
	*data++ = (char) n;

	return data;
}

static struct block *profiler_buffer_write(struct profiler_cpu_context *cpu_buf,
                                           struct block *b)
{
	if (b) {
		qibwrite(profiler_queue, b);

		if (qlen(profiler_queue) > profiler_queue_limit) {
			b = qget(profiler_queue);
			if (likely(b)) {
				cpu_buf->dropped_data_size += BLEN(b);
				freeb(b);
			}
		}
	}

	return block_alloc(profiler_cpu_buffer_size, MEM_ATOMIC);
}

static char *profiler_cpu_buffer_write_reserve(
	struct profiler_cpu_context *cpu_buf, size_t size, struct block **pb)
{
	struct block *b = cpu_buf->block;

	if (unlikely((!b) || (b->lim - b->wp) < size)) {
		cpu_buf->block = b = profiler_buffer_write(cpu_buf, b);
		if (unlikely(!b))
			return NULL;
	}
	*pb = b;

	return (char *) b->wp;
}

static inline void profiler_cpu_buffer_write_commit(
	struct profiler_cpu_context *cpu_buf, struct block *b, size_t size)
{
	b->wp += size;
}

static inline size_t profiler_max_envelope_size(void)
{
	return 2 * VBE_MAX_SIZE(uint64_t);
}

static void profiler_push_kernel_trace64(struct profiler_cpu_context *cpu_buf,
                                         const uintptr_t *trace, size_t count,
                                         uint64_t info)
{
	size_t size = sizeof(struct proftype_kern_trace64) +
		count * sizeof(uint64_t);
	struct block *b;
	void *resptr = profiler_cpu_buffer_write_reserve(
	    cpu_buf, size + profiler_max_envelope_size(), &b);
	void *ptr = resptr;

	if (likely(ptr)) {
		struct proftype_kern_trace64 *record;

		ptr = vb_encode_uint64(ptr, PROFTYPE_KERN_TRACE64);
		ptr = vb_encode_uint64(ptr, size);

		record = (struct proftype_kern_trace64 *) ptr;
		ptr += size;

		record->info = info;
		record->tstamp = nsec();
		record->cpu = cpu_buf->cpu;
		record->num_traces = count;
		for (size_t i = 0; i < count; i++)
			record->trace[i] = (uint64_t) trace[i];

		profiler_cpu_buffer_write_commit(cpu_buf, b, ptr - resptr);
	}
}

static void profiler_push_user_trace64(struct profiler_cpu_context *cpu_buf,
                                       struct proc *p, const uintptr_t *trace,
                                       size_t count, uint64_t info)
{
	size_t size = sizeof(struct proftype_user_trace64) +
		count * sizeof(uint64_t);
	struct block *b;
	void *resptr = profiler_cpu_buffer_write_reserve(
	    cpu_buf, size + profiler_max_envelope_size(), &b);
	void *ptr = resptr;

	if (likely(ptr)) {
		struct proftype_user_trace64 *record;

		ptr = vb_encode_uint64(ptr, PROFTYPE_USER_TRACE64);
		ptr = vb_encode_uint64(ptr, size);

		record = (struct proftype_user_trace64 *) ptr;
		ptr += size;

		record->info = info;
		record->tstamp = nsec();
		record->pid = p->pid;
		record->cpu = cpu_buf->cpu;
		record->num_traces = count;
		for (size_t i = 0; i < count; i++)
			record->trace[i] = (uint64_t) trace[i];

		profiler_cpu_buffer_write_commit(cpu_buf, b, ptr - resptr);
	}
}

static void profiler_push_pid_mmap(struct proc *p, uintptr_t addr, size_t msize,
                                   size_t offset, const char *path)
{
	size_t plen = strlen(path) + 1;
	size_t size = sizeof(struct proftype_pid_mmap64) + plen;
	void *resptr = kmalloc(size + profiler_max_envelope_size(), 0);

	if (likely(resptr)) {
		void *ptr = resptr;
		struct proftype_pid_mmap64 *record;

		ptr = vb_encode_uint64(ptr, PROFTYPE_PID_MMAP64);
		ptr = vb_encode_uint64(ptr, size);

		record = (struct proftype_pid_mmap64 *) ptr;
		ptr += size;

		record->tstamp = nsec();
		record->pid = p->pid;
		record->addr = addr;
		record->size = msize;
		record->offset = offset;
		memcpy(record->path, path, plen);

		qiwrite(profiler_queue, resptr, (int) (ptr - resptr));

		kfree(resptr);
	}
}

static void profiler_push_new_process(struct proc *p)
{
	size_t plen = strlen(p->binary_path) + 1;
	size_t size = sizeof(struct proftype_new_process) + plen;
	void *resptr = kmalloc(size + profiler_max_envelope_size(), 0);

	if (likely(resptr)) {
		void *ptr = resptr;
		struct proftype_new_process *record;

		ptr = vb_encode_uint64(ptr, PROFTYPE_NEW_PROCESS);
		ptr = vb_encode_uint64(ptr, size);

		record = (struct proftype_new_process *) ptr;
		ptr += size;

		record->tstamp = nsec();
		record->pid = p->pid;
		memcpy(record->path, p->binary_path, plen);

		qiwrite(profiler_queue, resptr, (int) (ptr - resptr));

		kfree(resptr);
	}
}

static void profiler_emit_current_system_status(void)
{
	void enum_proc(struct vm_region *vmr, void *opaque)
	{
		struct proc *p = (struct proc *) opaque;

		profiler_notify_mmap(p, vmr->vm_base, vmr->vm_end - vmr->vm_base,
		                     vmr->vm_prot, vmr->vm_flags, vmr->vm_file,
		                     vmr->vm_foff);
	}

	ERRSTACK(1);
	struct process_set pset;

	proc_get_set(&pset);
	if (waserror()) {
		proc_free_set(&pset);
		nexterror();
	}

	for (size_t i = 0; i < pset.num_processes; i++)
		enumerate_vmrs(pset.procs[i], enum_proc, pset.procs[i]);

	poperror();
	proc_free_set(&pset);
}

static void free_cpu_buffers(void)
{
	kfree(profiler_percpu_ctx);
	profiler_percpu_ctx = NULL;

	if (profiler_queue) {
		qfree(profiler_queue);
		profiler_queue = NULL;
	}
}

static void alloc_cpu_buffers(void)
{
	ERRSTACK(1);

	profiler_queue = qopen(profiler_queue_limit, 0, NULL, NULL);
	if (!profiler_queue)
		error(ENOMEM, ERROR_FIXME);
	if (waserror()) {
		free_cpu_buffers();
		nexterror();
	}

	qdropoverflow(profiler_queue, TRUE);

	profiler_percpu_ctx =
	    kzmalloc(sizeof(*profiler_percpu_ctx) * num_cores, MEM_WAIT);

	for (int i = 0; i < num_cores; i++) {
		struct profiler_cpu_context *b = &profiler_percpu_ctx[i];

		b->cpu = i;
	}
}

static long profiler_get_checked_value(const char *value, long k, long minval,
                                       long maxval)
{
	long lvalue = strtol(value, NULL, 0) * k;

	if (lvalue < minval)
		error(EFAIL, "Value should be greater than %ld", minval);
	if (lvalue > maxval)
		error(EFAIL, "Value should be lower than %ld", maxval);

	return lvalue;
}

int profiler_configure(struct cmdbuf *cb)
{
	if (!strcmp(cb->f[0], "prof_qlimit")) {
		if (cb->nf < 2)
			error(EFAIL, "prof_qlimit KB");
		if (kref_refcnt(&profiler_kref) > 0)
			error(EFAIL, "Profiler already running");
		profiler_queue_limit = (int) profiler_get_checked_value(
			cb->f[1], 1024, 1024 * 1024, max_pmem / 32);
		return 1;
	}
	if (!strcmp(cb->f[0], "prof_cpubufsz")) {
		if (cb->nf < 2)
			error(EFAIL, "prof_cpubufsz KB");
		profiler_cpu_buffer_size = (size_t) profiler_get_checked_value(
			cb->f[1], 1024, 16 * 1024, 1024 * 1024);
		return 1;
	}

	return 0;
}

void profiler_append_configure_usage(char *msgbuf, size_t buflen)
{
	const char * const cmds[] = {
		"prof_qlimit",
		"prof_cpubufsz",
	};

	for (int i = 0; i < ARRAY_SIZE(cmds); i++) {
		strlcat(msgbuf, "|", buflen);
		strlcat(msgbuf, cmds[i], buflen);
	}
}

static void profiler_release(struct kref *kref)
{
	bool got_reference = FALSE;

	assert(kref == &profiler_kref);
	qlock(&profiler_mtx);
	/* Make sure we did not race with profiler_setup(), that got the
	 * profiler_mtx lock just before us, and re-initialized the profiler
	 * for a new user.
	 * If we race here from another profiler_release() (user did a
	 * profiler_setup() immediately followed by a profiler_cleanup()) we are
	 * fine because free_cpu_buffers() can be called multiple times.
	 */
	if (!kref_get_not_zero(kref, 1))
		free_cpu_buffers();
	else
		got_reference = TRUE;
	qunlock(&profiler_mtx);
	/* We cannot call kref_put() within the profiler_kref lock, as such call
	 * might trigger anohter call to profiler_release().
	 */
	if (got_reference)
		kref_put(kref);
}

void profiler_init(void)
{
	assert(kref_refcnt(&profiler_kref) == 0);
	kref_init(&profiler_kref, profiler_release, 0);
}

void profiler_setup(void)
{
	ERRSTACK(1);

	qlock(&profiler_mtx);
	if (waserror()) {
		qunlock(&profiler_mtx);
		nexterror();
	}
	if (!profiler_queue)
		alloc_cpu_buffers();

	/* Do this only when everything is initialized (as last init operation).
	 */
	__kref_get(&profiler_kref, 1);

	profiler_emit_current_system_status();

	poperror();
	qunlock(&profiler_mtx);
}

void profiler_cleanup(void)
{
	kref_put(&profiler_kref);
}

static void profiler_cpu_flush(struct profiler_cpu_context *cpu_buf)
{
	if (cpu_buf->block && profiler_queue) {
		qibwrite(profiler_queue, cpu_buf->block);

		cpu_buf->block = NULL;
	}
}

static void profiler_core_trace_enable(void *opaque)
{
	struct profiler_cpu_context *cpu_buf = profiler_get_cpu_ctx(core_id());

	cpu_buf->tracing = (int) (opaque != NULL);
	if (!cpu_buf->tracing)
		profiler_cpu_flush(cpu_buf);
}

void profiler_control_trace(int onoff)
{
	struct core_set cset;

	error_assert(EINVAL, profiler_percpu_ctx);

	core_set_init(&cset);
	core_set_fill_available(&cset);
	smp_do_in_cores(&cset, profiler_core_trace_enable,
	                (void *) (uintptr_t) onoff);
}

static void profiler_core_flush(void *opaque)
{
	struct profiler_cpu_context *cpu_buf = profiler_get_cpu_ctx(core_id());

	profiler_cpu_flush(cpu_buf);
}

void profiler_trace_data_flush(void)
{
	struct core_set cset;

	error_assert(EINVAL, profiler_percpu_ctx);

	core_set_init(&cset);
	core_set_fill_available(&cset);
	smp_do_in_cores(&cset, profiler_core_flush, NULL);
}

void profiler_add_trace(uintptr_t pc, uint64_t info)
{
	if (is_user_raddr((void *) pc, 1))
		profiler_add_user_backtrace(pc, 0, info);
	else
		profiler_add_kernel_backtrace(pc, 0, info);
}

void profiler_add_kernel_backtrace(uintptr_t pc, uintptr_t fp, uint64_t info)
{
	if (kref_get_not_zero(&profiler_kref, 1)) {
		struct profiler_cpu_context *cpu_buf = profiler_get_cpu_ctx(core_id());

		if (profiler_percpu_ctx && cpu_buf->tracing) {
			uintptr_t trace[PROFILER_BT_DEPTH];
			size_t n = 1;

			trace[0] = pc;
			if (likely(fp))
				n = backtrace_list(pc, fp, trace + 1,
				                   PROFILER_BT_DEPTH - 1) + 1;

			profiler_push_kernel_trace64(cpu_buf, trace, n, info);
		}
		kref_put(&profiler_kref);
	}
}

void profiler_add_user_backtrace(uintptr_t pc, uintptr_t fp, uint64_t info)
{
	if (kref_get_not_zero(&profiler_kref, 1)) {
		struct proc *p = current;
		struct profiler_cpu_context *cpu_buf = profiler_get_cpu_ctx(core_id());

		if (p && profiler_percpu_ctx && cpu_buf->tracing) {
			uintptr_t trace[PROFILER_BT_DEPTH];
			size_t n = 1;

			trace[0] = pc;
			if (likely(fp))
				n = backtrace_user_list(pc, fp, trace + 1,
				                        PROFILER_BT_DEPTH - 1) + 1;

			profiler_push_user_trace64(cpu_buf, p, trace, n, info);
		}
		kref_put(&profiler_kref);
	}
}

void profiler_add_hw_sample(struct hw_trapframe *hw_tf, uint64_t info)
{
	if (in_kernel(hw_tf))
		profiler_add_kernel_backtrace(get_hwtf_pc(hw_tf), get_hwtf_fp(hw_tf),
		                              info);
	else
		profiler_add_user_backtrace(get_hwtf_pc(hw_tf), get_hwtf_fp(hw_tf),
		                            info);
}

int profiler_size(void)
{
	return profiler_queue ? qlen(profiler_queue) : 0;
}

int profiler_read(void *va, int n)
{
	return profiler_queue ? qread(profiler_queue, va, n) : 0;
}

void profiler_notify_mmap(struct proc *p, uintptr_t addr, size_t size, int prot,
                          int flags, struct file *f, size_t offset)
{
	if (kref_get_not_zero(&profiler_kref, 1)) {
		if (f && (prot & PROT_EXEC) && profiler_percpu_ctx) {
			char path_buf[PROFILER_MAX_PRG_PATH];
			char *path = file_abs_path(f, path_buf, sizeof(path_buf));

			if (likely(path))
				profiler_push_pid_mmap(p, addr, size, offset, path);
		}
		kref_put(&profiler_kref);
	}
}

void profiler_notify_new_process(struct proc *p)
{
	if (kref_get_not_zero(&profiler_kref, 1)) {
		if (profiler_percpu_ctx && p->binary_path)
			profiler_push_new_process(p);
		kref_put(&profiler_kref);
	}
}
