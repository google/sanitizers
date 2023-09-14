# MTE dynamic carveout resources

This page is a collection of resources for the MTE dynamic carveout
proposal.

* [Hardware requirements and operating system design sketch](./spec.md)
* [Prototype Linux kernel patch](https://github.com/pcc/linux/tree/mte-dynamic)
* [Prototype QEMU patch](https://github.com/pcc/qemu/tree/mte-dynamic)

## Usage

The patched QEMU may be instructed to expose the tag storage to
the guest, together with the device tree nodes expected by the
patched kernel, by passing the flag `mte-shared-alloc=on` as part
of the `-machine` command line argument. For example: `-machine
virt,virtualization=on,mte=on,mte-shared-alloc=on`.

Alternatively, when using a custom device tree, specific `memory`
and `reserved-memory` device tree nodes may be used to activate the
feature.

* The `arm,mte-alloc` attribute on a `memory` node indicates that any tag
  storage for that memory is described by `reserved-memory` nodes with the
  `compatible = "arm,mte-tag-storage"` attribute.

* The `arm,no-mte` attribute on a `memory` node indicates that the
  memory region is not capable of being mapped with the Tagged Normal
  attribute. At present this attribute may only be used if the memory
  region is fully covered by `reserved-memory` nodes with `compatible =
  "arm,mte-tag-storage"`.

* The `storage-base` attribute on a `reserved-memory` node with
  `compatible = "arm,mte-tag-storage"` specifies the physical address of
  the start of the MTE-capable memory region whose tag storage is described
  by the `reserved-memory` node.

## Limitations

* This implementation is not compatible with HW tag-based KASAN, nor
  with KVM with MTE-enabled VMs. If you try to use either of these features,
  you will probably crash the kernel.

* This implementation has some as-yet-undebugged issues which can cause
  kernel warnings about invalid page flags during certain memory-intensive
  operations.

* Automatic migration of pages between the tagged and untagged freelists
  is not yet implemented.
