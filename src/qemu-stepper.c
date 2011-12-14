#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#include "qemu.h"
#include "qemu-timer.h"
#include "kvm.h"

#include "nops.h"
#include "qemu-stepper.h"

unsigned long guest_stack_size = 8 * 1024 * 1024UL;
THREAD CPUState *thread_env;
int singlestep = 0;
unsigned long mmap_min_addr;
const char *qemu_uname_release = CONFIG_UNAME_RELEASE;
static uint64_t *idt_table;

void gemu_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

int cpu_get_pic_interrupt(CPUState *env)
{
    return -1;
}

void cpu_smm_update(CPUState *env)
{
}

uint64_t cpu_get_tsc(CPUX86State *env)
{
    return cpu_get_real_ticks();
}

void cpu_loop(CPUX86State *env)
{
	while (qemu_stepper_step(env) == 0);
}

void get_stack_size() {
	/* Read the stack limit from the kernel.  If it's "unlimited",
	then we can do little else besides use the default.  */
	{
		struct rlimit lim;
		if (getrlimit(RLIMIT_STACK, &lim) == 0
		&& lim.rlim_cur != RLIM_INFINITY
		&& lim.rlim_cur == (target_long)lim.rlim_cur) {
			guest_stack_size = lim.rlim_cur;
		}
	}
}

void *qemu_oom_check(void *ptr)
{
    if (ptr == NULL) {
        fprintf(stderr, "Failed to allocate memory.\n");
        abort();
    }
    return ptr;
}

void get_mmap_min_addr() {
	/*
	* Read in mmap_min_addr kernel parameter.  This value is used
	* When loading the ELF image to determine whether guest_base
	* is needed.  It is also used in mmap_find_vma.
	*/
	{
		FILE *fp;
		if ((fp = fopen("/proc/sys/vm/mmap_min_addr", "r")) != NULL) {
			unsigned long tmp;
			if (fscanf(fp, "%lu", &tmp) == 1) {
				mmap_min_addr = tmp;
				qemu_log("host mmap_min_addr=0x%lx\n", mmap_min_addr);
			}
			fclose(fp);
		}
	}
}
static void set_gate(void *ptr, unsigned int type, unsigned int dpl, uint32_t addr, unsigned int sel)
{
	uint32_t *p, e1, e2;
	e1 = (addr & 0xffff) | (sel << 16);
	e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
	p = ptr;
	p[0] = tswap32(e1);
	p[1] = tswap32(e2);
}

/* only dpl matters as we do only user space emulation */
static void set_idt(int n, unsigned int dpl)
{
	set_gate(idt_table + n, 0, dpl, 0, 0);
}

/* Assumes contents are already zeroed.  */
void init_task_state(TaskState *ts)
{
	int i;
	
	ts->used = 1;
	ts->first_free = ts->sigqueue_table;
	for (i = 0; i < MAX_SIGQUEUE_SIZE - 1; i++) {
		ts->sigqueue_table[i].next = &ts->sigqueue_table[i + 1];
	}
	ts->sigqueue_table[i].next = NULL;
}

TaskState * new_task_state() {
	TaskState *ts = qemu_mallocz (sizeof(TaskState));

	struct image_info *info = malloc(sizeof(struct image_info));
	struct linux_binprm *bprm = malloc(sizeof(struct linux_binprm));
	/* Zero out image_info */
	memset(info, 0, sizeof(struct image_info));
	memset(bprm, 0, sizeof(struct linux_binprm));
	
	init_task_state(ts);
	/* build Task State */
	ts->info = info;
	ts->bprm = bprm;
	ts->ts_tid = getpid();
	
	return ts;
}

static void write_dt(void *ptr, unsigned long addr, unsigned long limit, int flags)
{
	unsigned int e1, e2;
	uint32_t *p;
	e1 = (addr << 16) | (limit & 0xffff);
	e2 = ((addr >> 16) & 0xff) | (addr & 0xff000000) | (limit & 0x000f0000);
	e2 |= flags;
	p = ptr;
	p[0] = tswap32(e1);
	p[1] = tswap32(e2);
}

int info_prepare(struct image_info * info, abi_ulong code_len, abi_ulong stack_len) {
	abi_ulong codeblock = target_mmap(0, code_len + stack_len, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (codeblock == -1 ) {
		fprintf(stderr, "Unable to allocate RAM for process text/data\n");
		return -1;
	}
	
	/* Align stack.  */
	abi_ulong p = ((codeblock + code_len + stack_len + 3) & ~3) - 4;
	abi_ulong sp = p & ~(abi_ulong)(sizeof(abi_ulong) - 1);
	
	info->start_code = codeblock;
	info->end_code = info->start_data = info->end_data = info->start_brk = info->stack_limit = codeblock + code_len;
	info->start_stack = sp;
	return 0;
}
void info_set_entry(struct image_info * info, abi_ulong entry) {
	info->entry = (0x00ffffff & entry) + info->start_code;
}
void info_data_clean(struct image_info * info) {
	memset(info->start_code, 0, info->end_code - info->start_code);
}
void info_data_set(struct image_info * info, const unsigned char *ptr, abi_ulong size) {
	abi_ulong size_max = info->start_data;
	memcpy(info->start_code, ptr, (size > size_max) ? size_max : size);
	//gemu_log("ptrs: %x %x %x\n", info->start_code, info->stack_limit, info->start_stack);
	info->start_brk = size_max;
}
void info_apply(struct image_info * info, CPUState *env) {
	env->regs[R_EAX] = 0;
	env->regs[R_EBX] = 0;
	env->regs[R_ECX] = 0;
	env->regs[R_EDX] = 0;
	env->regs[R_ESI] = 0;
	env->regs[R_EDI] = 0;
	env->regs[R_EBP] = 0;
	env->regs[R_ESP] = info->start_stack;
	env->eip = info->entry;
	//fprintf(stderr,"qemu: entered 0x%x\n", env->eip);

	// Some hacks
	env->fpip = 0;
	env->fpuc = 0;
	env->fpus = 0;

	// More hacks
	env->cpuid_level = 0x0;
	env->cpuid_vendor1 = 0x0;
	env->cpuid_vendor2 = 0x0;
	env->cpuid_vendor3 = 0x0;
}



CPUX86State * qemu_stepper_init() {
	get_stack_size();
	get_mmap_min_addr();

	cpudef_setup(); /* parse cpu definitions in target config file (TBD) */

	cpu_exec_init_all(0);

	/* NOTE: we need to init the CPU at this stage to get qemu_host_page_size */
	CPUState *env = cpu_init("qemu32");
	cpu_reset(env);
	
	thread_env = env;
	env->opaque = new_task_state();

	signal_init();

	cpu_x86_set_cpl(env, 3);

	env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
	env->hflags |= HF_PE_MASK;
	if (env->cpuid_features & CPUID_SSE) {
		env->cr[4] |= CR4_OSFXSR_MASK;
		env->hflags |= HF_OSFXSR_MASK;
	}

	/* flags setup : we activate the IRQs by default as in user mode */
	env->eflags |= IF_MASK;

	env->idt.limit = 255;

	env->idt.base = target_mmap(0, sizeof(uint64_t) * (env->idt.limit + 1), PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	idt_table = g2h(env->idt.base);
	set_idt(0, 0);
	set_idt(1, 0);
	set_idt(2, 0);
	set_idt(3, 3);
	set_idt(4, 3);
	set_idt(5, 0);
	set_idt(6, 0);
	set_idt(7, 0);
	set_idt(8, 0);
	set_idt(9, 0);
	set_idt(10, 0);
	set_idt(11, 0);
	set_idt(12, 0);
	set_idt(13, 0);
	set_idt(14, 0);
	set_idt(15, 0);
	set_idt(16, 0);
	set_idt(17, 0);
	set_idt(18, 0);
	set_idt(19, 0);
	set_idt(0x2c, 3); /// TODO: what is 3?
	set_idt(0x80, 3);

	/* linux segment setup */
	{
		uint64_t *gdt_table;
		env->gdt.base = target_mmap(0, sizeof(uint64_t) * TARGET_GDT_ENTRIES,
					PROT_READ|PROT_WRITE,
					MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
		env->gdt.limit = sizeof(uint64_t) * TARGET_GDT_ENTRIES - 1;
		gdt_table = g2h(env->gdt.base);

		write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
			DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
			(3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));

		write_dt(&gdt_table[__USER_DS >> 3], 0, 0xfffff,
			DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
			(3 << DESC_DPL_SHIFT) | (0x2 << DESC_TYPE_SHIFT));
	}
	cpu_x86_load_seg(env, R_CS, __USER_CS);
	cpu_x86_load_seg(env, R_SS, __USER_DS);

	cpu_x86_load_seg(env, R_DS, __USER_DS);
	cpu_x86_load_seg(env, R_ES, __USER_DS);
	cpu_x86_load_seg(env, R_FS, __USER_DS);
	cpu_x86_load_seg(env, R_GS, __USER_DS);
	/* This hack makes Wine work... */
	env->segs[R_FS].selector = 0;

	return env;
}

void qemu_stepper_free(CPUX86State * env) {
	free(((TaskState *) env->opaque)->info);
	free(((TaskState *) env->opaque)->bprm);
	qemu_free(env); //cpu_x86_close(env);
}

int qemu_stepper_step(CPUX86State *env) {
	/* disable single step if it was enabled */
	cpu_single_step(env, 0);
	tb_flush(env);

	cpu_single_step(env, SSTEP_ENABLE|SSTEP_NOIRQ|SSTEP_NOTIMER);

	int trapnr = cpu_x86_exec(env);
	abi_ulong pc = env->segs[R_CS].base + env->eip;

	cpu_synchronize_state(env);

	switch(trapnr) {
		case EXCP_DEBUG: // We fall here after each normal step (because of cpu breakpoint).
			break;
		default:
			//gemu_log("qemu: 0x%08lx: got CPU interrupt 0x%x.\n", (long)pc, trapnr);
			return trapnr;
	}
	return 0;
}

int qemu_stepper_data_prepare(CPUState *env, unsigned long int code_len, unsigned long int stack_len) {
	struct image_info *info = ((TaskState *) env->opaque)->info;
	struct linux_binprm *bprm = ((TaskState *) env->opaque)->bprm;

	bprm->p = TARGET_PAGE_SIZE*MAX_ARG_PAGES-sizeof(unsigned int);
	memset(bprm->page, 0, sizeof(bprm->page));

	if (info_prepare(info, code_len, stack_len) >= 0) {
		return 0;
	}

	/* Something went wrong, return the inode and free the argument pages*/
	int i;
	for (i=0 ; i<MAX_ARG_PAGES ; i++) {
		free(bprm->page[i]);
	}
	return -1;
}
void qemu_stepper_stack_clear(CPUState *env) {
	struct image_info *info = ((TaskState *) env->opaque)->info;
	memset(info->stack_limit, 0, info->start_stack - info->stack_limit);
}
void qemu_stepper_data_set(CPUState *env, const unsigned char *ptr, unsigned long int size) {
	struct image_info *info = ((TaskState *) env->opaque)->info;
	info_data_set(info, ptr, size);
}
void qemu_stepper_entry_set(CPUState *env, unsigned long int entry, unsigned long int stack_offset) {
	struct image_info *info = ((TaskState *) env->opaque)->info;
	info_set_entry(info, entry);
	info_apply(info, env);
	env->regs[R_ESP] -= stack_offset;
}
unsigned long int qemu_stepper_eip(CPUState *env) {
	return env->segs[R_CS].base + env->eip;
}
int qemu_stepper_read(CPUState *env, char *buff, unsigned long int size) {
	return qemu_stepper_read_address(env, buff, size, env->eip, R_CS);
}
int qemu_stepper_read_code(CPUState *env, char *buff, unsigned long int size, unsigned long int address) {
	return qemu_stepper_read_address(env, buff, size, address, R_CS);
}
int qemu_stepper_read_address(CPUState *env, char *buff, unsigned long int size, unsigned long int address, unsigned int segment) {
	return cpu_memory_rw_debug(env, env->segs[segment].base + address, buff, size, 0);
}
unsigned long int qemu_stepper_register(CPUState *env, int regid) {
//	fprintf(stderr, "REG: 0x%x\n", env->regs[regid]);
	return env->regs[regid];
}
unsigned long int qemu_stepper_offset(CPUState *env) {
	struct image_info *info = ((TaskState *) env->opaque)->info;
	return info->start_code;
}

void qemu_stepper_print_debug(CPUX86State *env) {
	abi_ulong pc = env->segs[R_CS].base + env->eip;

	uint8_t buf[50];
	int len = 10;
	if (cpu_memory_rw_debug(env, pc, buf, len, 0) != 0) {
		gemu_log("Can't read memory from address 0x%x.\n", pc);
		return;
	}

	gemu_log("EIP: 0x%x\n", pc);
	gemu_log("REGS: eax=0x%x, ebx=0x%x, ecx=0x%x, edx=0x%x, esi=0x%x, edi=0x%x, ebp=0x%x, esp=0x%x.\n", env->regs[R_EAX], env->regs[R_EBX], env->regs[R_ECX], env->regs[R_EDX], env->regs[R_ESI], env->regs[R_EDI], env->regs[R_EBP], env->regs[R_ESP]);
	disas(stderr, buf, 10);
}