/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Copyright (C) 2025-2026  Joel Bueno
 *  Copyright (C) 2025-2026  Carlos López
 */

#ifndef PCIEM_API_H
#define PCIEM_API_H

#ifdef __KERNEL__
#include <linux/atomic.h>
#else
#include <stdatomic.h>
#include <stdint.h>
typedef atomic_int atomic_t;
#endif

#define PCIEM_MAX_FUNCTIONS         8

/** Mask to extract the bus mode bits from the flags field. */
#define PCIEM_CREATE_FLAG_BUS_MODE_MASK     0x00000003

/** Create a virtual PCIe bus owned entirely by PCIem. */
#define PCIEM_CREATE_FLAG_BUS_MODE_VIRTUAL  0x00000000

/** Attach to an existing physical PCIe bus. */
#define PCIEM_CREATE_FLAG_BUS_MODE_ATTACH   0x00000001

/**
 * Parameters for PCIEM_IOCTL_CREATE_DEVICE.
 *
 * @param flags     Bus-mode flags (PCIEM_CREATE_FLAG_BUS_MODE_*).
 * @param func      Function index to create (0–PCIEM_MAX_FUNCTIONS-1).
 *                  Must be 0 for the first function on a slot.
 *                  Functions 1–7 must be created after func 0.
 *                  For single-function devices, leave at 0 (zero-init is fine).
 * @param reserved  Must be zero.
 */
struct pciem_create_device
{
    uint32_t flags;
    uint8_t  func;
    uint8_t  reserved[3];
};

/**
 * Parameters for PCIEM_IOCTL_ADD_BAR.
 *
 * @param func  Function index this BAR belongs to (0–PCIEM_MAX_FUNCTIONS-1).
 *              Defaults to 0 if zero-initialised.
 */
struct pciem_bar_config
{
    uint32_t bar_index;
    uint32_t flags;
    uint64_t size;
    uint8_t  func;
    uint8_t  reserved[3];
};

struct pciem_cap_msi_userspace
{
    uint8_t num_vectors_log2;
    uint8_t has_64bit;
    uint8_t has_masking;
    uint8_t reserved;
};

struct pciem_cap_msix_userspace
{
    uint8_t bar_index;
    uint8_t reserved[3];
    uint32_t table_offset;
    uint32_t pba_offset;
    uint16_t table_size;
    uint16_t reserved2;
};

#define PCIEM_CAP_MSI 0
#define PCIEM_CAP_MSIX 1
#define PCIEM_CAP_PM 2
#define PCIEM_CAP_PCIE 3
#define PCIEM_CAP_VSEC 4
#define PCIEM_CAP_PASID 5

struct pciem_cap_pasid_userspace
{
    uint8_t  max_pasid_width;
    uint8_t  execute_permission;
    uint8_t  privileged_mode;
    uint8_t  reserved;
};

/**
 * Options of a PCIEM_CAP_PCIE capability.
 *
 * @param flags     PCIEM_CAP_PCIE_FLAG_*. Zero gives the capability pciem
 *                  always rendered: no Function Level Reset, so a function
 *                  with no PM capability has no reset method at all (it sits
 *                  alone on a root bus, so there is no bus reset either), and
 *                  vfio-pci does not offer VFIO_DEVICE_RESET. Unknown flags
 *                  fail with EINVAL.
 * @param reserved  Must be zero, or PCIEM_IOCTL_ADD_CAPABILITY fails with
 *                  EINVAL.
 */
struct pciem_cap_pcie_userspace
{
    uint8_t flags;
    uint8_t reserved[3];
};

/*
 * Advertise Function Level Reset (PCI_EXP_DEVCAP_FLR) and perform it when
 * the host sets PCI_EXP_DEVCTL_BCR_FLR; see "Reset" below.
 */
#define PCIEM_CAP_PCIE_FLAG_FLR (1 << 0)

/**
 * Parameters for PCIEM_IOCTL_ADD_CAPABILITY.
 *
 * @param func  Function index this capability belongs to (0–PCIEM_MAX_FUNCTIONS-1).
 *              Defaults to 0 if zero-initialised.
 */
struct pciem_cap_config
{
    uint32_t cap_type;
    uint8_t  func;
    uint8_t  reserved[3];
    union {
        struct pciem_cap_msi_userspace msi;
        struct pciem_cap_msix_userspace msix;
        struct pciem_cap_pasid_userspace pasid;
        struct pciem_cap_pcie_userspace pcie;
    };
};

/**
 * Parameters for PCIEM_IOCTL_SET_CONFIG.
 *
 * @param func  Function index to configure (0–PCIEM_MAX_FUNCTIONS-1).
 *              Defaults to 0 if zero-initialised.
 */
struct pciem_config_space
{
    uint8_t  func;
    uint8_t  reserved_func[3];
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t subsys_vendor_id;
    uint16_t subsys_device_id;
    uint8_t revision;
    uint8_t class_code[3];
    uint8_t header_type;
    uint8_t reserved[7];
};

struct pciem_event
{
    uint64_t seq;
    uint32_t type;
    uint32_t bar;
    uint64_t offset;
    uint32_t size;
    uint32_t reserved;
    uint64_t data;
    uint64_t timestamp;
};

#define PCIEM_EVENT_MMIO_READ 1
#define PCIEM_EVENT_MMIO_WRITE 2
#define PCIEM_EVENT_CONFIG_READ 3
#define PCIEM_EVENT_CONFIG_WRITE 4
#define PCIEM_EVENT_MSI_ACK 5
#define PCIEM_EVENT_RESET 6

/*
 * Reset.
 *
 * A function is reset by a Function Level Reset, if its PCIe capability has
 * PCIEM_CAP_PCIE_FLAG_FLR (the host sets PCI_EXP_DEVCTL_BCR_FLR), or by a PM
 * reset, if it has a PM capability (the host moves it from D3hot to D0, and
 * PCI_PM_CTRL_NO_SOFT_RESET, which pciem never sets, is clear). Linux resets
 * a function this way from pci_reset_function(): VFIO_DEVICE_RESET, a write
 * to /sys/bus/pci/devices/<bdf>/reset, and vfio-pci itself each time a user
 * opens the device and after the last user closes it. FLR comes first when
 * the function has both. A function with a PM capability is also reset
 * whenever it is woken from D3hot, which vfio-pci puts a device it has bound
 * in while nobody has it open (unless loaded with disable_idle_d3=1). pciem
 * does not model the power states otherwise: the BARs keep decoding in
 * D3hot.
 *
 * Before the device model hears of it, pciem has reset what it emulates, as
 * the reset does on hardware:
 *
 * - PCI_COMMAND reads 0 (no memory decode, no bus mastering, INTx enabled),
 *   and the error bits of PCI_STATUS are clear.
 * - The function's INTx line is deasserted, whether held by a level
 *   interrupt or by a pulse not delivered yet. The device model has to
 *   assert it again if it still wants to interrupt.
 * - The BAR registers read 0 (the address bits; the size and type bits stay).
 * - MSI: Message Control reads its read-only bits only (enable and Multiple
 *   Message Enable clear); address, data and mask bits read 0.
 * - MSI-X: Message Control reads the table size only (enable and function
 *   mask clear). The table and PBA are in BAR memory, which pciem leaves
 *   alone.
 * - PCIe: Device Control reads 0 apart from Max_Payload_Size, which FLR
 *   keeps. PASID Control reads 0.
 * - Synchronous reads (PCIEM_TRACE_SYNC_READS) waiting for an answer from
 *   the device model fail: the access returns all-ones, and an answer the
 *   device model writes for one afterwards fails with EINVAL.
 *
 * Linux then restores what it saved from config space before the reset,
 * MSI and MSI-X included, so the interrupts the host had set up keep working
 * without the device model doing anything.
 *
 * The device model gets one PCIEM_EVENT_RESET per reset, with @offset the
 * function index, @data PCIEM_RESET_FLR or PCIEM_RESET_PM, and @bar and
 * @size 0. It has to reset its own state: registers, queues, FIFOs,
 * anything in flight, and the BAR contents if it wants them reset (pciem
 * does not touch BAR memory, including the MSI-X table). A reset does not
 * stop MMIO: accesses to the BARs keep being delivered afterwards, the host
 * restoring the MSI-X table among them.
 *
 * Order: the event is queued once the reset of config state above is done.
 * It comes after the events of every access to the function traced before
 * the reset, and before those of every access traced after it. With the
 * ring full, pciem waits up to a second for the device model to make room;
 * failing that, the event goes out ahead of the function's next event
 * instead, and the kernel log says so. An answer to a read issued before the
 * reset can fail with EINVAL, and must not be taken as an error of the
 * device model. No acknowledgement is expected.
 *
 * VFIO_DEVICE_RESET waits for a read or write the vfio-pci user has in
 * progress on the device (vfio-pci takes its memory_lock for the reset), so
 * a synchronous read made through vfio-pci is never pending when that reset
 * happens: the reset waits for the answer, or for the read to time out.
 */

/* Kinds of reset. */
#define PCIEM_RESET_FLR 1
#define PCIEM_RESET_PM  2

struct pciem_response
{
    uint64_t seq;
    uint64_t data;
    int32_t status;
    uint32_t reserved;
};

/*
 * Interrupts.
 *
 * With MSI-X or MSI enabled by the host, PCIEM_IOCTL_INJECT_IRQ (flags 0)
 * and a plain irqfd send the given vector.
 *
 * Otherwise they use the function's INTx line (INTA). The line is either
 * asserted or not, as on hardware:
 *
 * - PCI_STATUS_INTERRUPT in config space reads the line.
 * - The host is interrupted when the line becomes asserted while
 *   PCI_COMMAND_INTX_DISABLE is clear, and again when the host clears
 *   INTX_DISABLE, or unmasks its irq, while the line is still asserted.
 *   Nothing reaches the host while INTX_DISABLE is set, nor on INTx while
 *   MSI or MSI-X is enabled.
 *
 * A level interrupt (PCIEM_IRQ_INJECT_FLAG_LEVEL, PCIEM_IRQFD_FLAG_LEVEL)
 * asserts the line and holds it until the device model deasserts it
 * (PCIEM_IRQ_INJECT_FLAG_DEASSERT, PCIEM_IRQFD_FLAG_DEASSERT). The vector is
 * ignored. This is what vfio-pci expects: its INTx handler sets INTX_DISABLE
 * and signals its user, and VFIO_IRQ_SET_ACTION_UNMASK, while
 * PCI_STATUS_INTERRUPT is still set, signals the user again and stays
 * masked instead of unmasking. So deassert when the host has serviced the
 * cause, e.g. on its write to the device's interrupt status register, and
 * before it unmasks, or it sees the interrupt once more.
 *
 * Without a flag, an INTx interrupt is a pulse: the line is asserted for one
 * run of the host's interrupt handler, then deasserted by pciem. A pulse
 * raised while INTX_DISABLE is set is held, without showing in
 * PCI_STATUS_INTERRUPT, and delivered once INTX_DISABLE is cleared; pulses
 * held together are delivered as one. This is how PCIEM_IOCTL_INJECT_IRQ with
 * zeroed flags always behaved when MSI was off, except that it used to reach
 * the host even with INTX_DISABLE set.
 *
 * A pulse or MSI with nowhere to go (no driver has bound yet, so the INTx
 * line is not routed, and no MSI) fails with -EINVAL, or, from an irqfd, is
 * dropped with a warning. A level assertion always succeeds: it sets the
 * line, and on a VIRTUAL bus the host is interrupted once it requests or
 * unmasks its irq.
 *
 * The rest of PCI_STATUS is read-only, except the error bits (parity,
 * target/master abort, system error), which are write-1-to-clear.
 */

/** Assert INTx and hold it (see "Interrupts" above). */
#define PCIEM_IRQ_INJECT_FLAG_LEVEL    (1 << 0)
/** Deassert INTx. Takes precedence over PCIEM_IRQ_INJECT_FLAG_LEVEL. */
#define PCIEM_IRQ_INJECT_FLAG_DEASSERT (1 << 1)

/**
 * Parameters for PCIEM_IOCTL_INJECT_IRQ.
 *
 * @param vector    MSI/MSI-X vector number to inject into the guest. Ignored
 *                  by PCIEM_IRQ_INJECT_FLAG_LEVEL and _DEASSERT.
 * @param func      Function index (0–PCIEM_MAX_FUNCTIONS-1).
 * @param flags     0 (vector or INTx pulse), or PCIEM_IRQ_INJECT_FLAG_*.
 *                  Unknown flags fail with -EINVAL.
 * @param reserved  Must be zero, or the ioctl fails with -EINVAL.
 */
struct pciem_irq_inject
{
    uint32_t vector;
    uint8_t func;
    uint8_t flags;
    uint8_t reserved[2];
};

struct pciem_dma_op
{
    uint64_t guest_iova;
    uint64_t user_addr;
    uint32_t length;
    uint32_t pasid;
    uint32_t flags;
    uint8_t func;
    uint8_t reserved[3];
};

#define PCIEM_DMA_FLAG_READ 0x1
#define PCIEM_DMA_FLAG_WRITE 0x2

struct pciem_dma_atomic
{
    uint64_t guest_iova;
    uint64_t operand;
    uint64_t compare;
    uint32_t op_type;
    uint32_t pasid;
    uint64_t result;
    uint8_t func;
};

#define PCIEM_ATOMIC_FETCH_ADD 1
#define PCIEM_ATOMIC_FETCH_SUB 2
#define PCIEM_ATOMIC_SWAP 3
#define PCIEM_ATOMIC_CAS 4
#define PCIEM_ATOMIC_FETCH_AND 5
#define PCIEM_ATOMIC_FETCH_OR 6
#define PCIEM_ATOMIC_FETCH_XOR 7

struct pciem_p2p_op_user
{
    uint64_t target_phys_addr;
    uint64_t user_addr;
    uint32_t length;
    uint32_t flags;
    uint8_t func;
};

/**
 * Parameters for PCIEM_IOCTL_GET_BAR_INFO.
 *
 * @param func  Function index to query (0–PCIEM_MAX_FUNCTIONS-1).
 *              Defaults to 0 if zero-initialised.
 */
struct pciem_bar_info_query
{
    uint32_t bar_index;
    uint64_t phys_addr;
    uint64_t size;
    uint32_t flags;
    uint8_t  func;
    uint8_t  reserved[3];
};

#define PCIEM_WP_FLAG_BAR_KPROBES  (1 << 0)
#define PCIEM_WP_FLAG_BAR_MANUAL   (1 << 1)

struct pciem_eventfd_config
{
    int32_t eventfd;
    uint32_t reserved;
};

struct pciem_irqfd_config
{
    int32_t eventfd;
    uint32_t vector;
    uint32_t flags;
    uint8_t func;
    uint8_t reserved[3];
};

/*
 * PCIEM_IOCTL_SET_IRQFD flags. Without either, each signal of the eventfd
 * injects @vector as PCIEM_IOCTL_INJECT_IRQ with flags 0 does; signals that
 * arrive before the previous one was injected are injected once.
 * PCIEM_IRQFD_FLAG_LEVEL makes each signal assert the function's INTx line
 * and hold it, and PCIEM_IRQFD_FLAG_DEASSERT (with or without _LEVEL) makes
 * each signal deassert it, in the order they are signalled; see "Interrupts"
 * above. Unknown flags fail with -EINVAL.
 */
#define PCIEM_IRQFD_FLAG_LEVEL    (1 << 0)
#define PCIEM_IRQFD_FLAG_DEASSERT (1 << 1)

struct pciem_dma_indirect
{
    uint64_t prp1;
    uint64_t prp2;
    uint64_t user_addr;
    uint32_t length;
    uint32_t page_size;
    uint32_t pasid;
    uint32_t flags;
    uint8_t func;
    uint8_t reserved[3];
};

/* Notify userspace on BAR reads */
#define PCIEM_TRACE_READS         (1 << 0)

/* Notify userspace on BAR writes */
#define PCIEM_TRACE_WRITES        (1 << 1)
/*
 * Normally, when PCIem detects a write to a BAR, it emulates that
 * write on its shadow mapping of the BAR, allowing future reads to
 * observe that write. If this flag is set, writes will still be
 * notified (if requested), but PCIem will not write to the BAR.
 * Userspace must update the BAR through its own mapping if it wants
 * the device driver to see updates to the BAR.
 */
#define PCIEM_TRACE_STOP_WRITES   (1 << 2)

/*
 * Route reads through userspace synchronously: the kernel pushes a
 * PCIEM_EVENT_MMIO_READ request onto the ring and waits until the device
 * model answers via write(fd, struct pciem_response). The response's @data
 * becomes the value the read returns. Required for destructive-read
 * registers (FIFO data ports).
 *
 * A read that vfio-pci makes for userspace (read() or write() on the device
 * fd, or an access through an mmap() of the BAR) sleeps while it waits. A
 * read from kernel code spins, because a fault cannot tell whether the code
 * that took it may sleep, so it is answered only while the device model can
 * run on another CPU: on a single CPU, or from an interrupt taken on the
 * device model's own CPU, it times out. The kernel reads an MSI-X table with
 * interrupts disabled when it masks a vector, so a range traced with this
 * flag must not share a page with the MSI-X table or PBA: PCIEM_IOCTL_TRACE_BAR
 * and PCIEM_IOCTL_TRACE_BAR_RANGES fail with EINVAL for such a trace (each
 * range is checked), and PCIEM_IOCTL_ADD_CAPABILITY fails with EINVAL for an
 * MSI-X capability whose table or PBA lies in a range already traced this
 * way. Leave the table's and PBA's pages out of the traced ranges, trace the
 * table's BAR with PCIEM_TRACE_WRITES alone, or leave it untraced.
 *
 * On timeout or a full ring the read returns all-1s, the value of a PCIe
 * master abort. For a destructive register, the value the device model
 * produced for that read is lost. */
#define PCIEM_TRACE_SYNC_READS    (1 << 3)

/**
 * Parameters for PCIEM_IOCTL_TRACE_BAR.
 *
 * @param func  Function index whose BAR should be traced (0–PCIEM_MAX_FUNCTIONS-1).
 *              Defaults to 0 if zero-initialised.
 */
struct pciem_trace_bar
{
    uint32_t bar_index;
    uint32_t flags;
    uint8_t  func;
    uint8_t  reserved[3];
};

/**
 * One traced part of a BAR, for PCIEM_IOCTL_TRACE_BAR_RANGES.
 *
 * @param offset  Start, from the start of the BAR. A multiple of the host
 *                page size (sysconf(_SC_PAGESIZE)).
 * @param length  Bytes. Nonzero, and a multiple of the host page size unless
 *                the range ends at the end of the BAR.
 */
struct pciem_trace_range
{
    uint64_t offset;
    uint64_t length;
};

#define PCIEM_TRACE_MAX_RANGES 64

/**
 * Parameters for PCIEM_IOCTL_TRACE_BAR_RANGES: trace only some parts of a BAR.
 *
 * Inside a range an access behaves exactly as in a BAR traced whole with
 * PCIEM_IOCTL_TRACE_BAR and the same @flags: the device model is notified, the
 * shadow is updated unless PCIEM_TRACE_STOP_WRITES, and PCIEM_TRACE_SYNC_READS
 * reads are answered by the device model. Event offsets are from the start of
 * the BAR, as always.
 *
 * Outside every range an access goes straight to the BAR's backing memory, as
 * for a BAR that is not traced, and the device model sees nothing: a vfio-pci
 * mmap() maps those pages (so memcpy() through it runs at memory speed, with
 * no faults after the first touch of each page), read()/write() on the vfio
 * device fd take vfio-pci's own path, and kernel ioremap() mappings are not
 * poisoned there. Poisoning works on whole page table leaves: where a range
 * shares a huge kernel mapping with untraced memory, x86 splits a 2 MiB leaf
 * into 4 KiB entries, but a 1 GiB leaf, and any huge leaf on arm64 and riscv,
 * is poisoned whole, so its untraced part still faults. Such a fault is served
 * from the backing memory without notifying the device model, as long as the
 * faulting instruction can be emulated.
 *
 * The ranges are fixed for as long as the BAR is traced: pass all of them in
 * one call. They are sorted by the kernel; adjacent ones are merged and
 * overlapping ones are rejected. A BAR is traced at most once, by either
 * ioctl: a call for a BAR already traced, or being set up by a concurrent
 * call, fails with EBUSY. With @nr_ranges 0 the whole BAR is traced, as by
 * PCIEM_IOCTL_TRACE_BAR.
 *
 * @param bar_index  BAR to trace.
 * @param flags      PCIEM_TRACE_*, as for PCIEM_IOCTL_TRACE_BAR.
 * @param func       Function index whose BAR should be traced.
 * @param reserved   Must be zero.
 * @param nr_ranges  Number of entries at @ranges, at most
 *                   PCIEM_TRACE_MAX_RANGES.
 * @param ranges     Userspace address of an array of struct pciem_trace_range.
 */
struct pciem_trace_bar_ranges
{
    uint32_t bar_index;
    uint32_t flags;
    uint8_t  func;
    uint8_t  reserved[3];
    uint32_t nr_ranges;
    uint64_t ranges;
};

#define PCIEM_IOCTL_MAGIC 0xAF

#define PCIEM_IOCTL_CREATE_DEVICE _IOWR(PCIEM_IOCTL_MAGIC, 10, struct pciem_create_device)
#define PCIEM_IOCTL_ADD_BAR _IOW(PCIEM_IOCTL_MAGIC, 11, struct pciem_bar_config)
#define PCIEM_IOCTL_ADD_CAPABILITY _IOW(PCIEM_IOCTL_MAGIC, 12, struct pciem_cap_config)
#define PCIEM_IOCTL_SET_CONFIG _IOW(PCIEM_IOCTL_MAGIC, 13, struct pciem_config_space)
#define PCIEM_IOCTL_REGISTER _IO(PCIEM_IOCTL_MAGIC, 14)
#define PCIEM_IOCTL_INJECT_IRQ _IOW(PCIEM_IOCTL_MAGIC, 15, struct pciem_irq_inject)
#define PCIEM_IOCTL_DMA _IOWR(PCIEM_IOCTL_MAGIC, 16, struct pciem_dma_op)
#define PCIEM_IOCTL_DMA_ATOMIC _IOWR(PCIEM_IOCTL_MAGIC, 17, struct pciem_dma_atomic)
#define PCIEM_IOCTL_P2P _IOWR(PCIEM_IOCTL_MAGIC, 18, struct pciem_p2p_op_user)
#define PCIEM_IOCTL_GET_BAR_INFO _IOWR(PCIEM_IOCTL_MAGIC, 19, struct pciem_bar_info_query)
#define PCIEM_IOCTL_SET_EVENTFD _IOW(PCIEM_IOCTL_MAGIC, 21, struct pciem_eventfd_config)
#define PCIEM_IOCTL_SET_IRQFD _IOW(PCIEM_IOCTL_MAGIC, 22, struct pciem_irqfd_config)
#define PCIEM_IOCTL_DMA_INDIRECT _IOWR(PCIEM_IOCTL_MAGIC, 24, struct pciem_dma_indirect)
#define PCIEM_IOCTL_TRACE_BAR _IOWR(PCIEM_IOCTL_MAGIC, 25, struct pciem_trace_bar)
#define PCIEM_IOCTL_START _IO(PCIEM_IOCTL_MAGIC, 26)
#define PCIEM_IOCTL_TRACE_BAR_RANGES _IOW(PCIEM_IOCTL_MAGIC, 27, struct pciem_trace_bar_ranges)

#define PCIEM_RING_SIZE 256
#define PCIEM_MAX_IRQFDS 32

/**
 * Lock-free single-producer/single-consumer event ring shared between the
 * kernel and userspace.
 *
 * The kernel writes events by advancing @tail; userspace consumes them by
 * advancing @head. Each counter is cache-line padded.
 * The ring is mapped read-only into userspace via mmap on the PCIem fd.
 *
 * @param head    Read index, owned by userspace. Incremented after each event
 *                is consumed.
 * @param _pad1   Cache-line padding to isolate @head from @tail.
 * @param tail    Write index, owned by the kernel. Incremented atomically
 *                after each event is committed.
 * @param _pad2   Cache-line padding to isolate @tail from the event array.
 * @param events  Circular buffer of PCIEM_RING_SIZE events.
 */
struct pciem_shared_ring
{
    atomic_t head;
    char _pad1[60];
    atomic_t tail;
    char _pad2[60];
    struct pciem_event events[PCIEM_RING_SIZE];
};

#endif /* PCIEM_API_H */
