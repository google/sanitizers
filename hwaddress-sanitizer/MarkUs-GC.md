# MarkUs-GC and HWASAN / MTE
Thoughts on the paper [MarkUs: Drop-in use-after-free prevention for
low-level languages](https://www.cl.cam.ac.uk/~tmj32/papers/docs/ainsworth20-sp.pdf).

TL;DR: MarkUs sounds interesting, although often costly. 
Combined with [Memory Tagging](hwaddress-sanitizer/MTE-iSecCon-2018.pdf) it becomes super interesting and *much less costly*. 

## MarkUs GC
The MarkUs paper suggests to use a GC-like mechanism to make heap-use-after-free (UAF) bugs unexploitable. 
The main advantage of MarkUs is that it doesn't change the semantics of C or C++ and thus can be deployed for existing code bases with relative ease. 
MarkUs does not detect UAFs.

Outline of MarkUs: 
* On free(), the memory region is placed into a quarantine. 
* From the user perspective, malloc/free work as usual, the language semantics don’t change. 
A program w/o UAFs will work the same way with and w/o MarkUs. 
If UAF actually happens, it is guaranteed to access quarantined memory.  
* When the quarantine size reaches a certain threshold, a GC-like scan 
marks all pointers accessible from live memory; then evicts all non-marked pointers 
from quarantine and thus allows them to be re-allocated. Marked pointers remain in quarantine.

## Weaknesses of MarkUs 

(this section is far from complete, suggestions are welcome)
In the context of C or C++, MarkUs may have certain weaknesses that may need to be addresses separately.
Despite these weaknesses, MarkUs sounds like an interesting approach to defeating UAF exploitabulity. 

### Spatial bugs

MarkUs ignores the existence of spatial bugs in C/C++, which weakens this scheme (a buffer overflow may still access free-d memory)

### Pointers to end

Pointers pointing past the end of allocations, like permitted by C++, makes MarkUs less efficient or less effective.
```
int *p = new int [8];
int *end = p + 8;  // valid C++, points past the end.
somewhere = end;
delete p;
<GC scan kicks in>
last = *(somewhere - 1); // UAF
```
If the heap allocator is header-less, “end” will point to the beginning of another heap chunk and thus the GC scan will not notice that ‘p’ is still accessible and will evict it from quarantine.

So, either the allocator needs to have headers / redzones between  the heap chunks (expensive, but tunable) or such UAFs will allow a bypass. 

### Pointer hiding
... is well explained in the paper 

## Overhead 
The not-so-good news is that MarkUs may have considerable overhead in CPU and/or RAM, as well as noticeable GC pauses. 
The paper gives a detailed description of the overheads.
Here is some "hand waving" based on my experiments. 

* The time required for a single GC scan is proportional to the memory that needs to be scanned, which is *roughly* the speed of RAM access.
So, a single-threaded application with a memory footprint of 1Gb may cause GC pauses of up to ~ `0.1s`
* The frequency of the GC scan is proportional to the speed of heap allocation (how many bytes are `malloc`-ed in second). 
So, a program that heap-allocates 100Mb per second, and can tolerate a 100Mb quarantine, will need to have a GC scan every second.  
* GC tends to parallelise well, but usually not linearly. 

So, roughly, the MarkUs CPU overhead is `O(MemoryFootprint * HeapAllocationSpeed / NumberOfThreads)`.
The RAM overhead of MarkUs depends on the qurantine and can be set by the user to an arbitrary value. 
The smaller is the quarantine, the more often you need to run the GC scan, i.e. we can trade RAM for CPU. 

## Possible Optimizations
* Bypass quarantine when a certain allocation is statically known to be safe. 
* Bypass quarantine when UAF-safety can be provided by some other means (e.g. for huge heap allocation we can use quarantine based on protecting parts of the virtual address space)
* Do not scan allocations known to not contain any pointers (e.g. allocations done on behalf of `std::string`)

## MarkUs and Memory Tagging
The authors write:
> ... MarkUs composes well with such techniques [memory tagging]. Not only
> does MarkUs provide the security that tagged memory lacks,
> and tagged memory the debug that MarkUs does not aim to
> provide, but tagged memory can also make MarkUs more
> efficient, by allowing reuse of memory multiple times, based
> on incrementing the ID tag of each successive allocation,
> before address space must be quarantined to ensure old IDs
> have been eliminated and can be reallocated.

Indeed so. With most implementations of memory tagging 
([HWASAN](https://clang.llvm.org/docs/HardwareAssistedAddressSanitizerDesign.html), 
[Arm MTE](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Arm_Memory_Tagging_Extension_Whitepaper.pdf), 
[SPARC ADI](https://www.kernel.org/doc/Documentation/sparc/adi.rst)) the following scheme is possible: 
* Every heap region is assigned a tag 0 on the first allocation. 
* On deallocation, the memory tag is incremented. If the tag has overflown, the memory chunk is put into MarkUs quarantine, 
otherwise it is returned to malloc free-lists and can be immediately reused. 

Why does this prevent UAFs? 

On the first allocation (`tag=0`), the given region of address space has not been used, so no UAF is possible. 
On the second allocation, we know that there might be a dangling pointer to the same region with `tag=0`, 
but the current allocation uses `tag=1`, so an access throught the old dangling pointer will generate a memory tagging trap.
On the `MaxTag`th allocation (i.e. in case of Arm or SPARC, on ~ 15th, in case of HWASAN, on 255th), 
we know that there are potentially dangling pointers with the tags `0, 1, ... MaxTag-1`, but not yet with MaxTag.
But as soon as we deallocate the `MaxTag`th allocation we can no longer assume complete UAF-safety because all the generations of this pointer are potentially dangling. This is when we run a GC scan and evict from quanrantine only those allocations versions of which are not found in the live memory.  

Thus, with e.g. Arm MTE, MarkUs will need 16x fewer scans, which makes MarkUs's perfomance compelling. 


Such deterministic tags assignment may cause memory tagging to be less effective against heap buffer overflows. 
The answer to that is to introduce some extra randomness into the tag creation. 
