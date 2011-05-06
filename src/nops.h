#ifndef NOPS_H
#define NOPS_H

void cpu_list_lock(void) {}
void cpu_list_unlock(void) {}

void cpu_outb(uint32_t addr, uint8_t val) {}
void cpu_outw(uint32_t addr, uint16_t val) {}
void cpu_outl(uint32_t addr, uint32_t val) {}
uint8_t cpu_inb(uint32_t addr) { return 0; }
uint16_t cpu_inw(uint32_t addr) { return 0; }
uint32_t cpu_inl(uint32_t addr) { return 0; }

#endif