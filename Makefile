QEMU	= $(CURDIR)/qemu-git
SRC	= $(CURDIR)/src
BUILD	= $(CURDIR)/build
PATCHES = $(CURDIR)/qemu-patches
CC	= gcc
FLAGS	= -D_NOLOCK -D_FORTIFY_SOURCE=2 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -Wstrict-prototypes -Wredundant-decls -Wall -Wundef -Wendif-labels -Wwrite-strings -Wmissing-prototypes -fno-strict-aliasing -fstack-protector-all -Wmissing-include-dirs -Wempty-body -Wnested-externs -Wformat-security -Wformat-y2k -Winit-self -Wignored-qualifiers -Wold-style-declaration -Wold-style-definition -Wtype-limits -O2 -fPIC
FLAGS1	= $(FLAGS) -I$(BUILD) -I$(SRC) -I$(QEMU) -I$(QEMU)/slirp -I$(CURDIR)
FLAGS2	= $(FLAGS1) -I$(QEMU)/target-i386 -DNEED_CPU_H -I$(QEMU)/linux-user/i386 -I$(QEMU)/linux-user -I$(QEMU)/fpu -I$(QEMU)/tcg -I$(QEMU)/tcg/i386
FLAGS3  = $(FLAGS) -I$(BUILD) -I$(SRC) -I$(QEMU)/target-i386 -DNEED_CPU_H -I$(QEMU)/linux-user/i386 -I$(QEMU)/linux-user

QEMU_MIRROR = git://repo.or.cz/qemu.git
#git://git.qemu.org/qemu.git

OBJECTS	=	$(BUILD)/mmap.o \
		$(BUILD)/qemu-malloc.o \
		$(BUILD)/tcg-runtime.o \
		$(BUILD)/cutils.o \
		$(BUILD)/i386-dis.o \
		$(BUILD)/exec.o \
		$(BUILD)/translate-all.o \
		$(BUILD)/cpu-exec.o \
		$(BUILD)/translate.o \
		$(BUILD)/tcg.o \
		$(BUILD)/softfloat.o \
		$(BUILD)/op_helper.o \
		$(BUILD)/helper.o \
		$(BUILD)/cpuid.o \
		$(BUILD)/disas.o \
		$(BUILD)/signal.o \
		$(BUILD)/user-exec.o \
		$(BUILD)/qemu-stepper.o

all: $(BUILD) $(QEMU) qemu-i386

lib: $(BUILD) $(QEMU) libqemu-stepper.so

$(BUILD):
	mkdir $(BUILD)

$(QEMU):
	git clone $(QEMU_MIRROR) qemu-git
	cd $(QEMU); git checkout .; git apply $(PATCHES)/*.patch

$(BUILD)/config-target.h:
	cd $(QEMU); ./configure \
			--target-list=i386-linux-user \
			--disable-docs \
			--disable-sdl \
			--disable-smartcard \
			--enable-kvm \
			--disable-vnc \
			--disable-bluez \
			--disable-nptl \
			--disable-curl \
			--disable-vde \
			--disable-attr \
			--disable-blobs \
			--disable-guest-base \
			--disable-werror \
			--audio-card-list= \
			--audio-drv-list= \
			--disable-curses
	sh $(QEMU)/scripts/create_config < $(QEMU)/config-host.mak > $(BUILD)/config-host.h
	sh $(QEMU)/scripts/create_config < $(QEMU)/i386-linux-user/config-target.mak > $(BUILD)/config-target.h
	sh $(QEMU)/scripts/tracetool --nop -h < $(QEMU)/trace-events > $(BUILD)/trace.h

$(BUILD)/config-host.h: $(BUILD)/config-target.h
$(BUILD)/trace.h: $(BUILD)/config-target.h

$(BUILD)/i386-dis.o: $(QEMU)/i386-dis.c
	$(CC) $(FLAGS1) -c -o $@ $(QEMU)/i386-dis.c

$(BUILD)/tcg-runtime.o: $(QEMU)/tcg-runtime.c
	$(CC) $(FLAGS1) -c -o $@ $(QEMU)/tcg-runtime.c

$(BUILD)/cutils.o: $(QEMU)/cutils.c
	$(CC) $(FLAGS1) -c -o $@ $(QEMU)/cutils.c

$(BUILD)/mmap.o: $(QEMU)/linux-user/mmap.c $(BUILD)/config-host.h $(BUILD)/config-target.h
	$(CC) $(FLAGS2) -c -o $@ $(QEMU)/linux-user/mmap.c

$(BUILD)/qemu-malloc.o: $(QEMU)/qemu-malloc.c $(BUILD)/trace.h
	$(CC) $(FLAGS2) -c -o $@ $(QEMU)/qemu-malloc.c

$(BUILD)/exec.o: $(QEMU)/exec.c
	$(CC) $(FLAGS2) -c -o $@ $(QEMU)/exec.c

$(BUILD)/translate-all.o: $(QEMU)/translate-all.c
	$(CC) $(FLAGS2) -c -o $@ $(QEMU)/translate-all.c

$(BUILD)/cpu-exec.o: $(QEMU)/cpu-exec.c
	$(CC) $(FLAGS2) -c -o $@ $(QEMU)/cpu-exec.c

$(BUILD)/translate.o: $(QEMU)/target-i386/translate.c
	$(CC) $(FLAGS2) -c -o $@ $(QEMU)/target-i386/translate.c

$(BUILD)/tcg.o: $(QEMU)/tcg/tcg.c
	$(CC) $(FLAGS2) -c -o $@ $(QEMU)/tcg/tcg.c

$(BUILD)/softfloat.o: $(QEMU)/fpu/softfloat.c
	$(CC) $(FLAGS2) -c -o $@ $(QEMU)/fpu/softfloat.c

$(BUILD)/op_helper.o: $(QEMU)/target-i386/op_helper.c
	$(CC) $(FLAGS2) -c -o $@ $(QEMU)/target-i386/op_helper.c

$(BUILD)/helper.o: $(QEMU)/target-i386/helper.c
	$(CC) $(FLAGS2) -c -o $@ $(QEMU)/target-i386/helper.c

$(BUILD)/cpuid.o: $(QEMU)/target-i386/cpuid.c
	$(CC) $(FLAGS2) -c -o $@ $(QEMU)/target-i386/cpuid.c

$(BUILD)/disas.o: $(QEMU)/disas.c
	$(CC) $(FLAGS2) -c -o $@ $(QEMU)/disas.c

$(BUILD)/user-exec.o: $(QEMU)/user-exec.c
	$(CC) $(FLAGS2) -c -o $@ $(QEMU)/user-exec.c

$(BUILD)/signal.o: $(SRC)/signal.c
	$(CC) $(FLAGS2) -c -o $@ $(SRC)/signal.c

$(BUILD)/qemu-stepper.o: $(SRC)/qemu-stepper.c $(SRC)/qemu-stepper.h
	$(CC) $(FLAGS2) -c -o $@ $(SRC)/qemu-stepper.c

$(BUILD)/main.o: $(SRC)/main.c $(SRC)/nops.h $(SRC)/qemu-stepper.h $(BUILD)/config-host.h $(BUILD)/config-target.h
	$(CC) $(FLAGS2) -c -o $@ $(SRC)/main.c

qemu-i386: $(BUILD)/main.o libqemu-stepper.so
	$(CC) $(FLAGS3) -o $@ $(BUILD)/main.o libqemu-stepper.so -Wl,-rpath -Wl,$(CURDIR)
	strip $@

libqemu-stepper.so: $(OBJECTS)
	$(CC) $(FLAGS3) -shared  -o $@ $(OBJECTS) -lrt -lpthread -lm
	strip $@

clean:
	rm -f *~ */*~ qemu-i386 libqemu-stepper.so $(OBJECTS) $(BUILD)/main.o $(BUILD)/config-target.h $(BUILD)/config-host.h $(BUILD)/trace.h

cleanbin:
	rm -f libqemu-stepper.so qemu-i386

relink: cleanbin qemu-i386

reset: clean
	rm -rf $(BUILD) $(QEMU)
