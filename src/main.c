#include <errno.h>
#include <sys/mman.h>

#include "qemu.h"
#include "qemu-stepper.h"


int main(int argc, char **argv)
{
	unsigned long int size = 0xd0, start = 0x0;


	unsigned char buffer[size];
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		printf("Error while loading %s\n", argv[1]);
	}
	pread(fd, &buffer, size, 0);
	close(fd);

	cpu_set_log_filename("/tmp/qemu.log");
	cpu_set_log(cpu_str_to_log_mask("in_asm,cpu"));

	CPUState *env = qemu_stepper_init();

	if (qemu_stepper_data_prepare(env, size, 0x100) != 0) {
		return 0;
	}

	qemu_stepper_data_set(env, &buffer, size);
	qemu_stepper_entry_set(env, start, 0x20);
	do {
		qemu_stepper_print_debug(env);
	} while (qemu_stepper_step(env) == 0);

	qemu_stepper_free(env);
	return 0;
}
