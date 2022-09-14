# MTE Dynamic tag storage

Peter Collingbourne &lt;[pcc@google.com](mailto:pcc@google.com)>

Evgenii Stepanov &lt;[eugenis@google.com](mailto:eugenis@google.com)>

## Definition

A Tag Block refers to 32 Data Pages together with 1 page of corresponding
tag storage for the Data Pages (the Tag Page). The number of available Tag
Blocks for a given DRAM size may be calculated as follows: (DRAM size /
Page size / 33).

## Goal

The goal is to allow an operating system running at EL1 to choose at
runtime whether to use a Tag Block to store untagged data (Data Pages
and Tag Page mapped as Normal memory) or to store tagged data (Data
Pages mapped as Tagged Normal memory), and to freely switch between them.

If the hardware meets optional requirements for relocatable Tag Blocks, a
hypervisor running at EL2 should be able to virtualize Tag Blocks without
knowing whether EL1 is using the Tag Block for tagged or untagged data.

## Base hardware requirements

1. Clean and invalidate of allocation tags to Point of Coherency (`DC
   CIGVAC, Xt`) over the Data Pages of a Tag Block followed by clean and
   invalidate of data to Point of Coherency (`DC CIVAC, Xt`) over the Tag Page,
   or a similar operation (referred to as a Tag Storage Clean operation),
   will put the memory system into a state where neither of the following
   can occur:
    a. Writeback of cached tags to the Tag Page.
    b. Writeback of cached data to the Tag Page, if the Tag Page was
       previously used to store untagged data.
2. Stores of data to a page mapped as Normal or Tagged Normal do not
   cause writeback of tags to the corresponding tag storage after a Tag
   Storage Clean operation.
3. Allocation tags are stored in regular RAM (not ECC) that can be
   mapped as Normal. This memory is coherent between CPUs (for regular
   memory access), but does not need to be coherent with allocation tag
   operations. If this memory is itself mapped as Tagged Normal (which should
   not happen!) then tag updates on it either raise a fault or do nothing,
   but never change the contents of any other page.

## Optional hardware requirements for relocatable Tag Blocks

1. If the Tag Storage Clean operation does not invalidate caches, the
   tag storage layout must be known.
2. After a Tag Storage Clean operation, a Tag Block may be copied to
   a different Tag Block at another PA. The copy operation shall access
   the memory using regular load and store instructions for both the Data
   Pages and the Tag Page. If the new Tag Block is mapped as Tagged Normal,
   the tags read at both locations shall be identical. If the Tag Storage
   Clean operation does not invalidate caches, the Tag Page data must be
   restored by writing it twice in order to ensure cache coherency: once via
   tag stores to the Data Page, and once via data stores to the Tag Page,
   according to the known tag storage layout.

## Operating system design

This is a sketch of how operating system software may use the dynamic
tag storage feature. It assumes a simple freelist-based page allocator.

* The operating system is notified of the location of the tag storage via
  a new device tree entry or ACPI table entry. From this it may determine
  the locations of the Tag Blocks. The device tree or ACPI table entry may
  be ignored by the operating system; this would only mean that it would
  not be able to use the tag storage for data.
* The system maintains three freelists: one for untagged pages, one for
  tagged pages and one for Tag Blocks.
* At system startup, the freelists for untagged and tagged pages are
  empty, and the Tag Block freelist contains all available Tag Blocks
  described by the device tree or ACPI.
* When a page is needed, the allocator first checks the appropriate page
  freelist (tagged or untagged). If no pages are available, a Tag Block
  is taken from the Tag Block freelist and converted into page freelist
  entries: 32 tagged pages (Data Pages) or 33 untagged pages (Data Pages +
  Tag Page).
* If no Tag Blocks are available either, the other page freelist
  is searched for groups of pages that may be converted into Tag Block
  freelist entries. Any groups found are removed from the page freelist
  and added to the Tag Block freelist, after performing a Tag Storage
  Clean operation on the Tag Block.
* If that operation fails to create Tag Blocks, we asynchronously
  start a compaction operation on the other page freelist where pages are
  consolidated into Tag Blocks, and the newly freed up Tag Blocks are Tag
  Storage Cleaned and added to the Tag Block freelist.
* While the compaction is taking place, we can immediately return untagged
  pages from the tagged freelist. To return a tagged page, we can look
  through the normal freelist for two pages. One of them must not be a tag
  page, and the other can be any page. Migrate the first page's tag page
  (if not free) to the second page, and return the first page.
* If that operation also fails to create Tag Blocks, it means that we
  are out of memory and it should be handled like any other OOM condition.

## Hypervisor design

This describes how a hypervisor may be built on top of a kernel supporting
the dynamic tag storage feature.

* A data abort or instruction abort, taken to EL2, in any part of a page,
  shall result in the allocation of a page from the tagged page freelist to
  the guest. This allows MTE to be used in the guest, but the underlying
  Tag Pages would not be exposed, so there would still be memory overhead
  from the unused Tag Pages, but only for those pages handed to the guest.
* Donating a page to the guest shall result in the corresponding Tag
  Page being hidden from the guest via stage 2 page tables. This will not
  result in the guest losing access to the tags in the other Data Pages
  in the Tag Block, because accessing tags via tag load/store instructions
  does not require permission to access the Tag Page, only the Data Page.
* Alternatively, if MTE is not enabled in the guest, pages handed to
  the guest may be allocated from the untagged page freelist, including
  Tag Pages.

Alternatively, a hypervisor may virtualize the dynamic tag storage
feature, which would allow the guest to make use of unused tag storage,
at the cost of requiring memory to be handed to the guest in Tag Block
sized chunks, potentially requiring compaction:

* Instead of virtualizing pages, the hypervisor virtualizes Tag Blocks. A
  device tree or ACPI table entry created by the hypervisor describes the
  location of the virtualized tag storage, so that the guest operating
  system knows the locations of the virtualized Tag Blocks.
* A data abort or instruction abort, taken to EL2, in any part of a
  virtualized Tag Block, shall result in the allocation of a physical Tag
  Block to the guest operating system. Both the Data Pages and the Tag
  Page will be exposed at the corresponding IPAs of the virtualized Tag
  Block via stage 2 page tables.
* If necessary, the hypervisor may remove a virtualized Tag Block from the
  stage 2 page table (e.g. if the Tag Block needs to be swapped out). When
  doing so, it shall perform a Tag Storage Clean operation before accessing
  the Tag Block directly.
* If a data abort or instruction abort is taken on a virtualized Tag Block
  that was previously removed from a stage 2 page table, the data will
  need to be restored to a physical Tag Block. The data may be restored
  to any available physical Tag Block, relying on the second hardware
  requirement for relocatable Tag Blocks to ensure that tags are preserved.
* Hardware that only supports the base hardware requirements and not the
  requirements for relocatable Tag Blocks may only support guests that do
  not release physical memory to the host, or only do so cooperatively. For
  example, this is how protected VM guests work.
