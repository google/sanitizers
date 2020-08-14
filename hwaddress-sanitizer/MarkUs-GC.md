# MarkUs-GC and HWASAN / MTE
Thoughts on the paper [MarkUs: Drop-in use-after-free prevention for
low-level languages](https://www.cl.cam.ac.uk/~tmj32/papers/docs/ainsworth20-sp.pdf).

TL;DR: MarkUs sounds interesting, although often costly. 
Combined with [Memory Tagging](hwaddress-sanitizer/MTE-iSecCon-2018.pdf) it becomes super interesting and much less costly. 

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


## Possible Optimizations
TODO

## MarkUs and Memory Tagging
TODO
