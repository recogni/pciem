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
 * Virtual-root mode only: put the device at @domain:@bus:00, the same address on
 * every host, instead of at the first free bus in domain 0. REGISTER fails with
 * -EEXIST if that bus is already taken.
 */
#define PCIEM_CREATE_FLAG_FIXED_ADDRESS     0x00000004

/** Bits 4-5 of the flags: where a virtual-root device sits; see "Topology" below. */
#define PCIEM_CREATE_FLAG_PLACEMENT_SHIFT 4
#define PCIEM_CREATE_FLAG_PLACEMENT_MASK  0x00000030
#define PCIEM_CREATE_FLAG_PLACEMENT(p)    ((uint32_t)(p) << PCIEM_CREATE_FLAG_PLACEMENT_SHIFT)
#define PCIEM_PLACEMENT_ROOT_BUS  0   /* on its root bus, as before */
#define PCIEM_PLACEMENT_ROOT_PORT 1   /* root bus -> Root Port -> device */
#define PCIEM_PLACEMENT_SWITCH    2   /* root bus -> Root Port -> switch Upstream Port -> Downstream Port -> device */

/**
 * Parameters for PCIEM_IOCTL_CREATE_DEVICE.
 *
 * @param flags     Bus-mode flags (PCIEM_CREATE_FLAG_BUS_MODE_*),
 *                  PCIEM_CREATE_FLAG_FIXED_ADDRESS and the placement
 *                  (PCIEM_CREATE_FLAG_PLACEMENT()). Bits not defined here
 *                  fail with EINVAL. A placement of 3, or other than
 *                  PCIEM_PLACEMENT_ROOT_BUS with a BUS_MODE_ATTACH, fails
 *                  with EINVAL; a function above 0 of a slot whose function 0
 *                  has a placement other than PCIEM_PLACEMENT_ROOT_BUS,
 *                  with EOPNOTSUPP.
 * @param func      Function index to create (0–PCIEM_MAX_FUNCTIONS-1).
 *                  Must be 0 for the first function on a slot.
 *                  Functions 1–7 must be created after func 0.
 *                  For single-function devices, leave at 0 (zero-init is fine).
 * @param bus       With PCIEM_CREATE_FLAG_FIXED_ADDRESS: the root bus number.
 * @param domain    With PCIEM_CREATE_FLAG_FIXED_ADDRESS: the PCI domain.
 */
struct pciem_create_device
{
    uint32_t flags;
    uint8_t  func;
    uint8_t  bus;
    uint16_t domain;
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
#define PCIEM_EVENT_LINK 7

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
 * function index, @data PCIEM_RESET_FLR, PCIEM_RESET_PM or, for a function
 * behind a port that got a hot reset (see "Topology"), PCIEM_RESET_HOT, and
 * @bar and @size 0. It has to reset its own state: registers, queues, FIFOs,
 * anything in flight, and the BAR contents if it wants them reset (pciem
 * does not touch BAR memory, including the MSI-X table). A reset does not
 * stop MMIO: accesses to the BARs keep being delivered afterwards, the host
 * restoring the MSI-X table among them.
 *
 * Order: the event is queued once the reset of config state above is done.
 * It comes after the events of every access to the function made before
 * the reset, and before those of every access made after it; an access made
 * while the function is being reset may come on either side. Like every
 * event, it has a larger @seq than the events ahead of it on the ring. With
 * the ring full, pciem waits up to a second for the device model to make
 * room; failing that, the event goes out ahead of the function's next event
 * instead, and the kernel log says so. A synchronous read ahead of the event
 * on the ring fails, and an answer to it fails with EINVAL, which must not be
 * taken as an error of the device model; one after the event is answered as
 * usual. No acknowledgement is expected.
 *
 * VFIO_DEVICE_RESET waits for a read or write the vfio-pci user has in
 * progress on the device (vfio-pci takes its memory_lock for the reset), so
 * a synchronous read made through vfio-pci is never pending when that reset
 * happens: the reset waits for the answer, or for the read to time out.
 */

/* Kinds of reset. */
#define PCIEM_RESET_FLR 1
#define PCIEM_RESET_PM  2
/* A hot reset (secondary bus reset) of the port above the function; see "Topology". */
#define PCIEM_RESET_HOT 3

/*
 * Link.
 *
 * A function's link can be taken down and brought back up, as a hot reset
 * of the link does on hardware: a device that reprograms its own SerDes
 * after enumeration holds its PCIe PIPE in reset, the LTSSM leaves L0 and
 * retrains, and the function comes back with its configuration space reset,
 * though the host asked for nothing. PCIEM_IOCTL_LINK (struct pciem_link)
 * does it to one function, and so does writing "down", or "up <speed>
 * <width>" (decimal, as in struct pciem_link), to
 * /sys/kernel/debug/pciem/<domain:bus:dev.fn>/link, a test control (root
 * only, there while the function is registered; reading it gives the state
 * in the same words), which drives the scenario without the device model
 * taking part. Both need a function with a PCIe capability, or fail with
 * EOPNOTSUPP, and refuse with EALREADY to take down a link that is down, or
 * bring up one that is up.
 *
 * While the link is down the function does not answer. The host is not
 * told (with PCIEM_PLACEMENT_ROOT_BUS; see "Topology" for the others):
 * there is no port above the function to report the link going down,
 * so nothing in Linux saves or restores anything, and nothing resets the
 * device. Interrupts and DMA stop: INJECT_IRQ fails with ENOLINK unless it
 * deasserts, an irqfd's interrupt is dropped, and DMA and P2P ioctls fail too.
 *
 * - A config read from the PCI core completes with all-ones, as a root port
 *   completes one that got no answer, so lspci, the sysfs config file, what
 *   vfio-pci reads from the device for its user, and the kernel's own
 *   accessors all read ff. A config write is dropped. Linux's view of the
 *   device (/sys/bus/pci/devices/<bdf>/vendor, enable and resource, its
 *   pci_dev) is what it was.
 * - A read of a traced part of a BAR returns all-ones and a write to one is
 *   dropped, whoever makes it (a kernel driver through ioremap(), a vfio-pci
 *   user through mmap(), read() or write(), a sysfs resource file), without
 *   reaching the device model: no PCIEM_EVENT_MMIO_* is queued. Untraced
 *   parts of a BAR, and pages of a mapping made before the BAR was traced,
 *   keep reading and writing the backing memory: pciem has no bus to answer
 *   for them.
 * - A synchronous read (PCIEM_TRACE_SYNC_READS) waiting for an answer fails
 *   as on a reset: the access returns all-ones, and an answer the device
 *   model writes for it afterwards fails with EINVAL.
 *
 * PCIEM_LINK_UP brings the function back as the retrain leaves it:
 *
 * - Its config state is reset exactly as a Function Level Reset resets it
 *   (see "Reset": PCI_COMMAND 0, the BARs 0 but for their size and type
 *   bits, INTx deasserted, MSI, MSI-X, PCIe Device Control and PASID at
 *   their reset values). Unlike after a reset, Linux restores nothing: the
 *   function stays with memory decoding off, its BARs unprogrammed and MSI
 *   and MSI-X disabled until the host's driver sets them up again, while
 *   /sys/bus/pci/devices/<bdf>/enable and resource, and the host's irq
 *   state, still say what they said before.
 * - Link Status reads the given speed (PCIEM_LINK_SPEED_*) and width, so
 *   lspci -vv shows the link as retrained: 32GT/s x16 after a retrain to
 *   Gen5, say, where it showed 5GT/s before. Max Link Speed and Maximum
 *   Link Width in Link Capabilities are raised to them if lower (pciem
 *   renders both as 0, unknown, to begin with); Link Capabilities 2 is
 *   left alone. Link Training and Data Link Layer Link Active are not
 *   modelled, and nothing else in the capability changes.
 * - BAR memory is not touched, the MSI-X table included: the device keeps
 *   its state through the retrain, as a chip does.
 *
 * The device model gets one PCIEM_EVENT_LINK per operation, with @offset
 * the function index, @data the op (PCIEM_LINK_DOWN or PCIEM_LINK_UP) in
 * bits 0-7 and, for PCIEM_LINK_UP, the speed in bits 8-15 and the width in
 * bits 16-23 (PCIEM_LINK_EVENT_SPEED_SHIFT, PCIEM_LINK_EVENT_WIDTH_SHIFT),
 * and @bar and @size 0. A model that retrains its own link, through the
 * ioctl, needs nothing from the event; one driven from the debugfs file
 * learns from it that the host has lost its configuration. pciem resets
 * nothing of the model's own state, and the event does not ask it to.
 *
 * Order: the event is queued before the link state changes, after the
 * function's unreported resets. It comes after the events of every access
 * to the function made before the operation and before those of every
 * access made after it; an access made while the link goes down or up may
 * come on either side, and is served as the link was when it was made. A
 * synchronous read ahead of a PCIEM_LINK_DOWN event on the ring fails, and
 * an answer to it fails with EINVAL, which must not be taken as an error of
 * the device model; one after the event is answered as usual. With the ring
 * full, pciem waits up to a second for the device model to make room, and
 * failing that the operation fails with ENOSPC and changes nothing. No
 * acknowledgement is expected.
 *
 * vfio-pci is not told either, and PCIEM_LINK_DOWN does not wait for a
 * read or write its user has in progress, as VFIO_DEVICE_RESET does by
 * taking memory_lock: a synchronous read in progress fails as above, and
 * an access already being served completes as it would have. A user that
 * resets the device afterwards (VFIO_DEVICE_RESET, which vfio-pci also does
 * on open and on the last close) resets a function that is reset already,
 * and gets its PCIEM_EVENT_RESET as usual.
 */

/* PCIEM_IOCTL_LINK operations, and the op of a PCIEM_EVENT_LINK. */
#define PCIEM_LINK_DOWN 1
#define PCIEM_LINK_UP   2
/* PCIEM_IOCTL_LINK only, not an event op: equalization above @speed fails (0: no limit); see "Topology". */
#define PCIEM_LINK_EQ_LIMIT 3

/* Link speeds: the encoding of Current Link Speed in Link Status. */
#define PCIEM_LINK_SPEED_2_5GT 1
#define PCIEM_LINK_SPEED_5GT   2
#define PCIEM_LINK_SPEED_8GT   3
#define PCIEM_LINK_SPEED_16GT  4
#define PCIEM_LINK_SPEED_32GT  5
#define PCIEM_LINK_SPEED_64GT  6

/* Where a PCIEM_LINK_UP's speed and width sit in a PCIEM_EVENT_LINK's @data. */
#define PCIEM_LINK_EVENT_SPEED_SHIFT 8
#define PCIEM_LINK_EVENT_WIDTH_SHIFT 16

/**
 * Parameters for PCIEM_IOCTL_LINK; see "Link" above.
 *
 * @param func   Function index (0–PCIEM_MAX_FUNCTIONS-1).
 * @param op     PCIEM_LINK_DOWN or PCIEM_LINK_UP, or PCIEM_LINK_EQ_LIMIT
 *               (function 0 of a device with a placement other than
 *               PCIEM_PLACEMENT_ROOT_BUS, or EOPNOTSUPP): @speed 0 to
 *               PCIEM_LINK_SPEED_64GT, @width 0.
 * @param speed  PCIEM_LINK_UP: the speed the link comes back at,
 *               PCIEM_LINK_SPEED_*. Must be 0 for PCIEM_LINK_DOWN.
 * @param width  PCIEM_LINK_UP: the width the link comes back at: 1, 2, 4,
 *               8, 12, 16 or 32. Must be 0 for PCIEM_LINK_DOWN.
 * @param flags  Must be zero.
 *
 * Anything else fails with EINVAL.
 */
struct pciem_link
{
    uint8_t  func;
    uint8_t  op;
    uint8_t  speed;
    uint8_t  width;
    uint32_t flags;
};

/*
 * Topology.
 *
 * A virtual-root device is placed with two bits of the flags of
 * PCIEM_IOCTL_CREATE_DEVICE (PCIEM_CREATE_FLAG_PLACEMENT()), on function 0;
 * pciem gives the device its own host bridge, and, below it:
 *
 * - PCIEM_PLACEMENT_ROOT_BUS: nothing. The device is function 0 on its root
 *   bus, N:00.0, as it always was. Nothing in this section applies to it,
 *   except the trace and the debugfs files "trace", "trace_ctl" and
 *   "topology".
 * - PCIEM_PLACEMENT_ROOT_PORT: a Root Port at N:00.0, and the device at
 *   N+1:00.0. The host bridge's bus window is [N, N+1].
 * - PCIEM_PLACEMENT_SWITCH: one switch that many devices share. The switch
 *   has a Root Port at N:00.0 (secondary N+1, subordinate N+2+P), an Upstream
 *   Port at N+1:00.0 (secondary N+2), and P Downstream Ports, port k at
 *   N+2:k.0 (secondary and subordinate N+3+k). The device on port k is at
 *   N+3+k:00.0. The host bridge's bus window is [N, N+2+P]. P is
 *   struct pciem_topology @switch_ports and the device picks its port with
 *   @port.
 *
 * N is the first free bus range of the needed size in domain 0, or the
 * domain and bus of PCIEM_CREATE_FLAG_FIXED_ADDRESS. A switch placement
 * needs PCIEM_CREATE_FLAG_FIXED_ADDRESS: N is the Root Port's bus, the same
 * for every device of the switch. Registration is serialised, so the
 * numbering is deterministic: on a host with only bus 00, the device k of a
 * series that all take the same placement sits at k+1 (root bus) or 2k+2
 * (Root Port). A placement other than PCIEM_PLACEMENT_ROOT_BUS needs
 * PCIEM_CREATE_FLAG_BUS_MODE_VIRTUAL, and is for single-function devices. An
 * older pciem.ko does not know the placement bits and ignores them, so a
 * caller that needs one checks where the device landed (the depth of its
 * path in /sys/bus/pci/devices, 1, 2 or 4). A placed device whose REGISTER
 * fails can only be closed: a second REGISTER fails with EINVAL.
 *
 * Shared switch. The first device to REGISTER at (domain, N) creates the
 * switch: the host bridge, the Root Port, the Upstream Port and all P
 * Downstream Ports, and one pool region of P equal chunks for the BARs of
 * the devices, the size of the first device's chunk. A later device with the
 * same N joins it. Its @switch_ports, @flags and the @rp_*, @dsp_* fields
 * must equal the first device's, or REGISTER fails with EINVAL; a port that
 * is taken fails with EBUSY, and a BAR layout larger than one chunk with
 * ENOSPC. REGISTER of a device waits (module parameter train_timeout_ms) for
 * its Downstream Port's link to reach L0 and then scans the port's bus; a
 * Downstream Port with no device has no link partner and stays in
 * Detect.Quiet. The switch lasts until the last of its devices unregisters
 * or has its file descriptor closed, in any order; a device that leaves
 * removes only its own function and brings its port's link down, and a
 * device that registers on the freed port again gets a fresh link.
 *
 * pciem acts as the platform firmware: before the host scans the bus it
 * writes the primary, secondary and subordinate bus numbers of every bridge,
 * lays the device's BARs out in one chunk of the pool, programs each
 * bridge's prefetchable window to cover that chunk (in a switch, the Root
 * Port's and the Upstream Port's cover the whole region and Downstream Port
 * k's covers chunk k), and clears Command. The
 * host then claims what it finds instead of reassigning it, so a BAR never
 * moves. BAR memory is not routed through the bridges: the windows and the
 * Command bits are stored and read back, and nothing else uses them. A
 * device with only prefetchable BARs has no memory window; one with
 * non-prefetchable BARs needs them below 4 GiB, or REGISTER fails with
 * EINVAL.
 *
 * The bridges are PCI-to-PCI bridges with PCIe capability version 2. Their
 * IDs are vendor 0x1eb2, device 0xd130 (Root Port), 0xd131 (Upstream Port)
 * and 0xd132 (Downstream Port); class 0x060400. Modelled: the type 1
 * header (no I/O window, no BARs, Interrupt Pin 0), the memory and
 * prefetchable windows, Bridge Control, the PCIe capability with Link and
 * Slot registers (Slot Capabilities report a present device and no
 * power controller; Hot-Plug only with PCIEM_TOPO_FLAG_HOTPLUG), one-vector
 * MSI on the Root Port and the Downstream Port, an AER capability and a PM
 * capability (version 3, No_Soft_Reset set, the power state bits are stored
 * and nothing else is powered down; with it Linux waits for a port's link
 * after a Secondary Bus Reset before it restores what is below). Not
 * modelled: ASPM and Clock PM, SR-IOV, ARI, a Gen3/Gen4+ equalization
 * control with lane registers, and any traffic through a bridge. The Root
 * Port and every Downstream Port have an ACS extended capability: Source
 * Validation, Translation Blocking, P2P Request Redirect, P2P Completion
 * Redirect and Upstream Forwarding, all writable and all enabled at reset.
 * With them enabled each device of a switch is in its own IOMMU group.
 *
 * Link. The Root Port, and in a switch each Downstream Port, drives a
 * link to the next function with a small LTSSM (the Link Training and Status
 * State Machine) whose state names, in the order a link visits them, are
 * Detect.Quiet, Detect.Active, Polling.Active, Polling.Configuration,
 * Configuration.Linkwidth, Configuration.Lanenum, Configuration.Complete,
 * Configuration.Idle, L0, Recovery.RcvrLock, Recovery.RcvrCfg,
 * Recovery.Speed, Recovery.Equalization.Phase1 to Phase3, Recovery.Idle,
 * HotReset and Disabled. The time spent in each state is a model
 * parameter, in microseconds, not a measurement; the defaults are at the
 * scale of the PCIe Base Specification's timeouts (a 12 ms Detect.Quiet
 * and so on), set with the module parameter ltssm_us ("key=value,...") and
 * per link in the debugfs file "timing".
 *
 * A link trains up to L0 at 2.5GT/s, with the width of the narrower end.
 * Data Link Layer Link Active (DLLLA) follows a few microseconds later
 * (DL_Up), the device becomes reachable, and Slot Status DLLSC is set.
 * After a short settle time the link steps up, through Recovery, to the
 * target speed: the lowest of the Target Link Speed of the port's Link
 * Control 2 (TLS), the port's maximum, the partner's maximum, and any
 * limit left by a failed equalization. A step goes from 2.5GT/s to 5GT/s
 * if that is the target, and otherwise to 8GT/s, 16GT/s and 32GT/s in turn
 * (5GT/s is skipped). A rate of 8GT/s or more equalizes once per link
 * training before it is used. The link equalizes unless the device's
 * equalization limit (PCIEM_LINK_EQ_LIMIT, struct pciem_topology
 * @eq_fail_above) is below the rate: then Phase 2 of the equalization
 * times out, the link returns to the previous rate, the rate and the ones
 * above it are excluded until the next Detect, a retrain or a change of
 * the limit, and the link steps up to the highest rate still allowed
 * (which needs no equalization up to 5GT/s). With a limit of 5GT/s
 * (PCIEM_LINK_SPEED_5GT) the link comes up at 5GT/s with Link Bandwidth
 * Management Status (LBMS) set, as a link does that cannot equalize.
 *
 * Link Status semantics. Link Training (LT) is 1 in every Configuration and
 * Recovery state and 0 otherwise. LBMS is set at the end of a Recovery that
 * a write of Retrain Link started, and when the hardware changes speed or
 * width for reliability (a failed equalization, a Recovery that times out
 * and trains down). Link Autonomous Bandwidth Status (LABS) is set when the
 * link steps up by itself after DL_Up, not after a Retrain Link. Neither
 * is set by the link coming up from DL_Down. Both are write-1-to-clear and
 * raise the port's interrupt when set, if Link Control enables it. LNKSTA
 * Current Link Speed and Negotiated Link Width change when L0 is entered.
 * DLLSC is set at every change of DLLLA.
 *
 * Config responses. While the link above a function is not in DL_Up (or is
 * in HotReset or Disabled), a config read of anything behind the port
 * completes with all-ones and a write is dropped, as an Unsupported Request
 * does. For @rrs_ms after each DL_Up (struct pciem_topology; the module
 * parameter rrs_ms, default 0, none) the device answers Configuration
 * Request Retry Status (RRS) instead: a read that covers its Vendor ID
 * returns 0001h in the low half, with ffffh above it in a dword read, if
 * the Root Port's Root Control has RRS Software Visibility enabled (Linux
 * does, in pci_enable_rrs_sv()); any other read in that time returns
 * all-ones, and writes are dropped.
 * Functions on a bus with no device at that slot answer
 * PCIBIOS_DEVICE_NOT_FOUND, as always.
 *
 * With a placement other than PCIEM_PLACEMENT_ROOT_BUS, PCIEM_LINK_DOWN and
 * PCIEM_LINK_UP act on the link above the device (the Root Port's in
 * PCIEM_PLACEMENT_ROOT_PORT, the device's own Downstream Port's in
 * PCIEM_PLACEMENT_SWITCH, which leaves the other devices alone) and the host
 * is told: "Link" above stops being true. PCIEM_LINK_DOWN
 * makes the device stop answering at once; the partner is then gone, the
 * link falls to Recovery and, after recovery_timeout, to Detect.Quiet with
 * DLLLA 0, Negotiated Link Width 0, Current Link Speed 2.5GT/s and DLLSC
 * set; that DL_Down resets the device's config state. PCIEM_LINK_UP makes the
 * partner present again; the ioctl returns while the link trains, and the
 * device is reachable once DL_Up is reached, after the RRS window. A
 * PCIEM_LINK_UP within recovery_timeout resumes Recovery in DL_Up. Reading
 * the debugfs "link" file gives "down" until then. Either must not
 * be repeated: EALREADY is judged on what the device last asked for, not on
 * where the link is. PCIEM_LINK_EQ_LIMIT sets the equalization limit of
 * the device's link (@speed, 0 for none, with @width 0); it takes effect
 * at the next equalization and does not retrain. While the device is not
 * reachable, interrupts and DMA stop as "Link" describes.
 *
 * The host operates the ports as on hardware, in config writes:
 *
 * - Retrain Link (Link Control bit 5), in L0, takes the link through
 *   Recovery to the current target speed, up or down, and sets LBMS. It
 *   clears the exclusions of a failed equalization first. LT is 1
 *   from the write until the link is back in L0. It is ignored outside L0.
 * - A write of Target Link Speed is stored, and caps the next training or
 *   retrain. It does not retrain by itself.
 * - Link Disable puts the link in Disabled with DL_Down, and clearing it in
 *   Detect.Quiet. Linux uses it before it resets a port. Its DL_Down resets
 *   the device's config state, as every DL_Down of the device's link does.
 * - Secondary Bus Reset (Bridge Control bit 6), 0 to 1, puts the link in
 *   HotReset with DL_Down, and resets the device as a Function Level Reset
 *   does: the device model gets PCIEM_EVENT_RESET with @data PCIEM_RESET_HOT.
 *   Setting it on a Root Port in switch placement resets the switch
 *   too: the Upstream Port and every Downstream Port go back to their
 *   power-on config (bus numbers and windows 0), every Downstream Port's link
 *   goes to HotReset and stays there until the Root Port's link is up again,
 *   and every device of the switch gets the reset event. Setting it on the
 *   Upstream Port does the same for the Downstream Ports and the devices.
 *   Setting it on Downstream Port k resets device k only. When
 *   it clears again, after the link has spent hot_reset microseconds in
 *   HotReset it goes to Detect.Quiet and trains; a device whose link was
 *   down stays down. Linux's pci_reset_secondary_bus() waits 2 ms with the
 *   bit set, and then waits for the link; with the defaults DL_Up comes
 *   some 15 ms after the bit clears, and the steps to the target speed
 *   follow.
 * - Linux's pcie_failed_link_retrain() (a quirk) retrains a downstream link
 *   to 2.5GT/s when, after a reset wait, DLLLA is 0 and LBMS has been seen.
 *   A link whose equalization limit makes it train to a lower speed with
 *   LBMS set, and then goes down and comes back later than the host's wait
 *   (about a second), can arm it; the kernel logs it.
 *
 * Options, in struct pciem_topology @flags, off by default as on the
 * hardware this models:
 *
 * - PCIEM_TOPO_FLAG_HOTPLUG: the port above the device is Hot-Plug Capable
 *   and Surprise Hot-Plug capable; Slot Status DLLSC and PDC raise its
 *   interrupt when Slot Control enables it, and pciehp removes and
 *   re-enumerates the device on link down and up. DMA fails with ENODEV
 *   from the removal until Linux enumerates the device again.
 * - PCIEM_TOPO_FLAG_NATIVE_AER: the host bridge grants Linux AER and DPC
 *   (native_aer, native_dpc), so the AER and DPC drivers bind to the Root
 *   Port. Without it Linux leaves them to the firmware and does nothing.
 * - PCIEM_TOPO_FLAG_UNMASK_SDES: the Uncorrectable Error Mask of the
 *   ports resets without Surprise Down masked. A link that goes down other
 *   than by a reset, a Link Disable or a hot reset from above then sets
 *   Uncorrectable Error Status SDES on the port, which reports it to the Root
 *   Port as an error message that sets Root Error Status and its
 *   interrupt, if the Device and Root Control bits allow it. In a switch the
 *   one Root Port receives the messages of all the Downstream Ports.
 * - PCIEM_TOPO_FLAG_DPC: the downstream-facing ports have a DPC capability
 *   (control and status registers only: the trigger is never modelled).
 *
 * Interrupts. The Root Port and each Downstream Port have one MSI vector.
 * A port raises it on a rising edge of LBMS or LABS with its enable in Link
 * Control (LBMIE, LABIE), of DLLSC, PDC or CC of Slot Status with the
 * hot-plug interrupt enable and the matching enable, and, for the Root Port,
 * of a Root Error Status bit with its Root Error Command enable. If the
 * port's MSI is not enabled, or the vector has no interrupt, the request is
 * dropped and not repeated.
 *
 * Trace. Each device keeps a ring of the last pciem.trace_records (default
 * 16384, at least 1024) records of what happened on its links and ports, one
 * JSON object a line, read from /sys/kernel/debug/pciem/<domain:bus:dev.fn>/
 * (root only, <bdf> of function 0, the device). In a switch the device's ring
 * has the records of its own Downstream Port and endpoint; the Root Port's
 * and the Upstream Port's go to a ring of the switch, in
 * /sys/kernel/debug/pciem/switch-<domain>:<bus>/ (the Root Port's bus), with
 * the files "trace", "trace_ctl", "topology" and "rp/" below, which lasts as
 * long as the switch. Both have the same record schema.
 *
 *   trace      JSON lines of the ring, oldest first, as a snapshot. Every
 *              line has t (ktime_get_ns()), seq (per device), ev and fn (rp,
 *              usp, dsp, ep0..ep7, none). ev is cfg (a config access,
 *              with pciem.trace_cfg set: bus, devfn, op, off, len, val,
 *              res), ltssm (from, to, speed, width, why), dl (up, speed,
 *              width), lnksta (old, new, cls, nlw, lt, dllla, lbms, labs,
 *              why), sltsta and aer (reg, old, new, why), ctl (what, val),
 *              link_op (op, speed, width, src), reset (kind), irq (cause,
 *              vec, sent), phase (name, lc) or mark (text, lc), lc being
 *              local_clock(), which relates printk times to t. When
 *              records were overwritten the first line is ev "lost" with
 *              n the count.
 *   trace_ctl  write "clear" or "mark <text>".
 *   topology   one JSON object: the placement, the bus range, and the
 *              BDF, role and bus numbers of every function. A device of a
 *              switch lists the shared Root Port and Upstream Port, its own
 *              Downstream Port and its endpoint, with "port" and
 *              "switch_ports"; the switch's lists every function.
 *   rp/ and dsp/ (the ports that drive a link): "state" (one line of
 *              key=value), "eq_limit" (a rate code, 0 for none), "timing"
 *              (read all keys, write "key=value ..."), "rrs_ms".
 *
 * and the module parameters trace_cfg, trace_ep_irq, trace_records,
 * ltssm_us, eq_fail_above, rrs_ms and train_timeout_ms (how long REGISTER
 * waits for the links to settle before it scans, default 1000 ms).
 */

#define PCIEM_TOPO_FLAG_HOTPLUG     (1u << 0) /* port above the device: Slot Hot-Plug Capable + Surprise */
#define PCIEM_TOPO_FLAG_NATIVE_AER  (1u << 1) /* host bridge grants Linux AER and DPC (native_aer/native_dpc) */
#define PCIEM_TOPO_FLAG_UNMASK_SDES (1u << 2) /* AER UEMsk resets without Surprise Down masked */
#define PCIEM_TOPO_FLAG_DPC         (1u << 3) /* DPC extended capability on downstream-facing ports */

/** Most Downstream Ports a switch placement has. */
#define PCIEM_SWITCH_MAX_PORTS 32

/** @eq_fail_above value for no limit. */
#define PCIEM_EQ_LIMIT_NONE 0xff

/**
 * Parameters for PCIEM_IOCTL_SET_TOPOLOGY; see "Topology" above. Zero
 * fields take defaults. Allowed between PCIEM_IOCTL_CREATE_DEVICE and
 * PCIEM_IOCTL_REGISTER, for a device with a placement other than
 * PCIEM_PLACEMENT_ROOT_BUS: EINVAL otherwise, or for a bad speed or width,
 * a reserved field that is not zero, an unknown flag, @port or
 * @switch_ports set with another placement than PCIEM_PLACEMENT_SWITCH, a
 * switch without @switch_ports or with a @port that is not below it, or a
 * switch without PCIEM_CREATE_FLAG_FIXED_ADDRESS (checked at REGISTER too);
 * EBUSY after REGISTER. A switch placement needs it: REGISTER without it
 * fails with EINVAL.
 *
 * @param flags          PCIEM_TOPO_FLAG_*.
 * @param rp_speed       Root Port Max Link Speed (PCIEM_LINK_SPEED_*).
 *                       Default 32GT/s.
 * @param rp_width       Root Port width. Default 16.
 * @param dsp_speed      Switch Downstream Port speed; 0 with
 *                       PCIEM_PLACEMENT_ROOT_PORT. Default 32GT/s.
 * @param dsp_width      Switch Downstream Port width. Default 8.
 * @param ep_speed       The device's Max Link Speed (its Link Capabilities).
 *                       Default 32GT/s.
 * @param ep_width       The device's Maximum Link Width. Default 8.
 * @param eq_fail_above  The device's link: equalization to a rate above this
 *                       fails. 0: the module parameter eq_fail_above;
 *                       PCIEM_EQ_LIMIT_NONE: no limit.
 * @param rrs_ms         The device answers Configuration RRS this long after
 *                       each DL_Up. 0: the module parameter rrs_ms.
 * @param port           PCIEM_PLACEMENT_SWITCH: the Downstream Port the
 *                       device attaches to, 0..switch_ports-1. 0 otherwise.
 * @param switch_ports   PCIEM_PLACEMENT_SWITCH: the number of Downstream
 *                       Ports of the switch, 1..PCIEM_SWITCH_MAX_PORTS. 0
 *                       otherwise. Every device of the switch passes the
 *                       same value.
 */
struct pciem_topology
{
    uint32_t flags;
    uint8_t  rp_speed;
    uint8_t  rp_width;
    uint8_t  dsp_speed;
    uint8_t  dsp_width;
    uint8_t  ep_speed;
    uint8_t  ep_width;
    uint8_t  eq_fail_above;
    uint8_t  port;
    uint16_t rrs_ms;
    uint16_t switch_ports;
    uint32_t reserved[4];
};

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
 * With MSI-X or MSI enabled by the host and by the function's own Enable bit,
 * PCIEM_IOCTL_INJECT_IRQ with flags 0 and a plain irqfd send the given vector.
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
 * dropped with a warning. A level assertion while the link is up sets the
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
#define PCIEM_IOCTL_LINK _IOW(PCIEM_IOCTL_MAGIC, 28, struct pciem_link)
#define PCIEM_IOCTL_SET_TOPOLOGY _IOW(PCIEM_IOCTL_MAGIC, 29, struct pciem_topology)

#define PCIEM_RING_SIZE 256
#define PCIEM_MAX_IRQFDS 32

/**
 * Lock-free single-producer/single-consumer event ring shared between the
 * kernel and userspace.
 *
 * The kernel writes events by advancing @tail; userspace consumes them by
 * advancing @head. Each counter is cache-line padded. The @seq of the
 * events increases along the ring.
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
