#include "lab.h"
#include <assert.h>
#include <signal.h>   
#include <execinfo.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif

#include "lab.h"

#define handle_error_and_die(msg)   \
    do {                            \
        perror(msg);                \
        raise(SIGKILL);             \
    } while (0)

/**
 * Converts bytes to its equivalent K value defined as bytes <= 2^K
 */
size_t btok(size_t bytes) {
    size_t kval = 0;
    while ((UINT64_C(1) << kval) < bytes) 
        kval++;
    if (kval < SMALLEST_K) {
        kval = SMALLEST_K;
    }
    return kval;
}

/**
 * Find the buddy of a given pointer and kval relative to the base address.
 */
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *block) 
{
    uintptr_t offset = (uintptr_t)block - (uintptr_t)pool->base;
    uintptr_t toggle = UINT64_C(1) << block->kval;
    uintptr_t rval = (offset ^ toggle);
    uintptr_t bud = rval + (uintptr_t)pool->base;
    struct avail *tmp = (struct avail *)bud;
    return tmp;
}

/**
 * Initialize a new memory pool using the buddy algorithm.
 */
void buddy_init(struct buddy_pool *pool, size_t size) {
    if (size == 0) {
        size = UINT64_C(1) << DEFAULT_K;
    } else {
        size = UINT64_C(1) << btok(size);
    }

    if (size < (UINT64_C(1) << MIN_K)) {
        size = UINT64_C(1) << MIN_K;
    }

    pool->numbytes = size;
    pool->kval_m = btok(size);
    pool->base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (pool->base == MAP_FAILED) {
        pool->base = NULL;
        return;
    }

    for (size_t i = 0; i <= pool->kval_m; i++) {
        pool->avail[i].tag = BLOCK_UNUSED;
        pool->avail[i].kval = i;
        pool->avail[i].next = &pool->avail[i];
        pool->avail[i].prev = &pool->avail[i];
    }

    pool->avail[pool->kval_m].tag = BLOCK_AVAIL;
    pool->avail[pool->kval_m].next = (struct avail *)pool->base;
    pool->avail[pool->kval_m].prev = (struct avail *)pool->base;

    struct avail *base_block = (struct avail *)pool->base;
    base_block->tag = BLOCK_AVAIL;
    base_block->kval = pool->kval_m;
    base_block->next = &pool->avail[pool->kval_m];
    base_block->prev = &pool->avail[pool->kval_m];
}

/**
 * Allocates a block of memory from the buddy pool.
 */
void *buddy_malloc(struct buddy_pool *pool, size_t size) {
    if (size == 0) {
        return NULL;
    }
    // Get kval foor requested size with enough room foor tag & kval fields
    size_t kval = btok(size + sizeof(struct avail));
    assert(size < (UINT64_C(1) << kval));
    size_t j = kval;

    // R1 Find a block
    while (j <= pool->kval_m && pool->avail[j].next == &pool->avail[j]) {
        j++;
    }

    // There waasn't enough memory to sattiisfy the requestt thuus we need tto set error andd return NULL
    if (j > pool->kval_m) {
        errno = ENOMEM;
        return NULL;
    }

    //R2 Remove from list
    struct avail *block = pool->avail[j].next;
    assert(rval->kval ==j);
    assert(rval->tag == BLOCK_AVAIL);
    struct avail *p = rval->next;
    pool->avail[j].next = p;
    p->prev = &pool->avail[j];
    rval->tag = BLOCK_RESERVED;

    //R3 Split required?
    while (j != kval)
    {
        //R4 split thee block
        j--;
        struct avail *buddy = (struct avail *)((uintptr_t)block + (UINT64_C(1) << j));
        buddy->tag = BLOCK_AVAIL;
        buddy->kval = j;
        buddy->next = &pool->avail[j];
        //Make sure list is actually empty before we addd in nother block
        assert(pool->avail[j].next == &pool->avail[j]);
        assert(pool->avail[j].prev == &pool->avail[j]);
        pool->avail[j].next = pool->avail[j].prev = buddy;
    }
    rval->kval=kval;
    rval->next = rval->prev = NULL; // Clean up pointers
    assertt(rval->tag == BLOCK_RESERVED);
    return (rval + 1); // Return pointer to the memory after the avail
}

/**
 * Allocates a block of memory from the buddy pool.
 */
// void *buddy_malloc(struct buddy_pool *pool, size_t size) {
//     if (!pool || size == 0) {
//         errno = ENOMEM;
//         return NULL;
//     }

//     size_t k = btok(size + sizeof(struct avail));
//     if (k < SMALLEST_K) {
//         k = SMALLEST_K;
//     }

//     for (size_t i = k; i <= pool->kval_m; i++) {
//         if (pool->avail[i].next != &pool->avail[i]) {
//             // printf("[malloc] Found block at %p with kval=%zu for request of %zu bytes (k=%zu)\n", (void *)block, block->kval, size, k); // Debugging line
//             struct avail *block = pool->avail[i].next;

//             // Remove block from the free list
//             block->prev->next = block->next;
//             block->next->prev = block->prev;
//             if (pool->avail[i].next == &pool->avail[i]) {
//                 pool->avail[i].tag = BLOCK_UNUSED;  // Mark list as empty
//             }
            

//             block->kval = i; 
//             while (i > k) {
//                 i--;
//                 block->kval = i;
//                 struct avail *buddy = (struct avail *)((uintptr_t)block + (UINT64_C(1) << i));
//                 buddy->tag = BLOCK_AVAIL;
//                 buddy->kval = i;
//                 buddy->next = &pool->avail[i];
//                 buddy->prev = pool->avail[i].prev;
//                 pool->avail[i].prev->next = buddy;
//                 pool->avail[i].prev = buddy;
//                 pool->avail[i].tag = BLOCK_AVAIL;
//             }

//             block->tag = BLOCK_RESERVED;
//             block->kval = k;
//             return (void *)(block + 1);
//         }
//     }

//     errno = ENOMEM;
//     return NULL;
// }


/**
 * Frees a previously allocated block of memory.
 */
void buddy_free(struct buddy_pool *pool, void *ptr) {
    if (ptr == NULL) {
        return;
    }
    struct avail *free_me = (struct avail *)ptr - 1;
    struct avail *buddy = buddy_calc(pool, free_me);

    //S1 Is buuddy avvailable?
    while (free_me->kval != pool->kval_m && 
            buddy->tag == BLOCK_AVAIL && 
            free_me->kval == buddy->kval) 
        {
        assert (buddy->next != NULL);
        assert (buddy->prev != NULL);
        
        //S2 Remove buddy from list
        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;
        if (buddy < free_me)
            free_me = buddy;
        free_me->kval++;
        buddy = buddy_calc(pool, free_me);
        }

        //S3 Put in list
        free_me->tag = BLOCK_AVAIL;
        struct avail *p = pool->avail[free_me->kval].next;
        free_me->next = p;
        p->prev = free_me;
        free_me->prev = &pool->avail[free_me->kval];
        pool->avail[free_me->kval].next = free_me;    
}

/**
 * Frees a previously allocated block of memory.
 */
// void buddy_free(struct buddy_pool *pool, void *ptr) {
//     if (!pool || !ptr) {
//         return;
//     }

//     struct avail *block = (struct avail *)ptr - 1;
//     // printf("[free] Releasing block at %p with kval=%zu\n", (void *)block, block->kval); // Debugging line
//     while (block->kval < pool->kval_m) {
//         struct avail *buddy = buddy_calc(pool, block);
//         if (buddy->tag != BLOCK_AVAIL || buddy->kval != block->kval) {
//             break;
//         }

//         // Remove buddy from the free list
//         buddy->prev->next = buddy->next;
//         buddy->next->prev = buddy->prev;

//         buddy->next = buddy->prev = NULL; // Clean up pointers

//         if (buddy < block) {
//             block = buddy;
//         }

//         block->kval++;
//     }

//     block->tag = BLOCK_AVAIL;
//     block->next = &pool->avail[block->kval];
//     block->prev = pool->avail[block->kval].prev;
//     pool->avail[block->kval].prev->next = block;
//     pool->avail[block->kval].prev = block;
// }


/**
 * Changes the size of a memory block.
 */
void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size) {
    if (!ptr) {
        return buddy_malloc(pool, size);
    }

    if (size == 0) {
        buddy_free(pool, ptr);
        return NULL;
    }

    struct avail *block = (struct avail *)ptr - 1;
    size_t old_size = UINT64_C(1) << block->kval;

    if (size + sizeof(struct avail) <= old_size) {
        return ptr;
    }

    void *new_ptr = buddy_malloc(pool, size);
    if (new_ptr) {
        memcpy(new_ptr, ptr, old_size - sizeof(struct avail));
        buddy_free(pool, ptr);
    }

    return new_ptr;
}

/**
 * Destroys the buddy memory pool.
 */
void buddy_destroy(struct buddy_pool *pool) {
    if (pool && pool->base) {
        munmap(pool->base, pool->numbytes);
        pool->base = NULL;
    }
}