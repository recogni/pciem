KDIR ?= /lib/modules/$(shell uname -r)/build

# Checked in the kbuild pass, where the target kernel's version and .config
# are known, so a kernel pciem cannot build against fails with one clear
# message instead of compile errors.
ifneq ($(KERNELRELEASE),)
PCIEM_MIN_VERSION := 6
PCIEM_MIN_PATCHLEVEL := 8
ifneq ($(shell [ $(VERSION) -gt $(PCIEM_MIN_VERSION) ] || \
               [ $(VERSION) -eq $(PCIEM_MIN_VERSION) -a $(PATCHLEVEL) -ge $(PCIEM_MIN_PATCHLEVEL) ] && echo y),y)
$(error pciem needs Linux $(PCIEM_MIN_VERSION).$(PCIEM_MIN_PATCHLEVEL) or later; this kernel is $(KERNELRELEASE))
endif
# smptrace traps BAR accesses with kprobes and kretprobes
ifneq ($(CONFIG_KPROBES)$(CONFIG_KRETPROBES),yy)
$(error pciem needs a kernel built with CONFIG_KPROBES=y and CONFIG_KRETPROBES=y; $(KERNELRELEASE) has CONFIG_KPROBES=$(or $(CONFIG_KPROBES),n) CONFIG_KRETPROBES=$(or $(CONFIG_KRETPROBES),n))
endif
endif

ccflags-y := -I$(src)/../include -I$(src)/include

pciem-objs := framework/pciem.o \
              framework/capabilities.o \
              framework/p2p.o \
              framework/dma.o \
              framework/userspace.o \
              framework/pool.o \
              framework/iommu_stub.o \
              framework/msi_domain.o

pciem-objs += trace/smptrace.o \
              trace/smptrace_user.o \
              trace/smptrace_vfio.o \
              trace/smptrace_sysfs.o \
              trace/arch/$(ARCH)/smptrace_arch.o

ifeq ($(ARCH),x86)
pciem-objs += trace/arch/x86/lib/insn.o \
              trace/arch/x86/lib/insn-eval.o \
              trace/arch/x86/lib/inat.o
ccflags-y += -I$(src)/trace/arch/x86/include/asm
endif

obj-m += pciem.o

ccflags-y += -Wall

# Only add build rules when not invoked by kbuild
ifeq ($(KERNELRELEASE),)
all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean
endif
