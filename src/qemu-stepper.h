#ifndef QEMU_STEPPER_H
#define QEMU_STEPPER_H

CPUState * qemu_stepper_init();
void qemu_stepper_free(CPUState * env);
int qemu_stepper_step(CPUState *env);
int qemu_stepper_data_prepare(CPUState *env, unsigned long int code_len, unsigned long int stack_len);
void qemu_stepper_data_set(CPUState *env, const unsigned char *ptr, unsigned long int size);
void qemu_stepper_entry_set(CPUState *env, unsigned long int entry, unsigned long int stack_offset);
unsigned long int qemu_stepper_eip(CPUState *env);
int qemu_stepper_read(CPUState *env, char *buff, unsigned long int size);
void qemu_stepper_print_debug(CPUState *env);
unsigned long int qemu_stepper_register(CPUState *env, int regid);
unsigned long int qemu_stepper_offset(CPUState *env);
#endif