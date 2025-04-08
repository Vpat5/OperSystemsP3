#include "lab.h"
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

/**
 * Converts bytes to its equivalent K value defined as bytes <= 2^K
 */
size_t btok(size_t bytes) {
    size_t k = 0;
    size_t total = 1;
    while (total < bytes) {
        total <<= 1;
        k++;
    }
    return k;
}

/**
 * Find the buddy of a given pointer and kval relative to the base address.
 */
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *block) {
    uintptr_t offset = (uintptr_t)block - (uintptr_t)pool->base;
    uintptr_t buddy_offset = offset ^ (UINT64_C(1) << block->kval);
    return (struct avail *)((uintptr_t)pool->base + buddy_offset);
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
    if (!pool || size == 0) {
        errno = ENOMEM;
        return NULL;
    }

    size_t k = btok(size + sizeof(struct avail));
    if (k < SMALLEST_K) {
        k = SMALLEST_K;
    }

    for (size_t i = k; i <= pool->kval_m; i++) {
        if (pool->avail[i].next != &pool->avail[i]) {
            struct avail *block = pool->avail[i].next;

            // Remove block from the free list
            block->prev->next = block->next;
            block->next->prev = block->prev;

            while (i > k) {
                i--;
                struct avail *buddy = (struct avail *)((uintptr_t)block + (UINT64_C(1) << i));
                buddy->tag = BLOCK_AVAIL;
                buddy->kval = i;
                buddy->next = &pool->avail[i];
                buddy->prev = pool->avail[i].prev;
                pool->avail[i].prev->next = buddy;
                pool->avail[i].prev = buddy;
            }

            block->tag = BLOCK_RESERVED;
            block->kval = k;
            return (void *)(block + 1);
        }
    }

    errno = ENOMEM;
    return NULL;
}

/**
 * Frees a previously allocated block of memory.
 */
void buddy_free(struct buddy_pool *pool, void *ptr) {
    if (!pool || !ptr) {
        return;
    }

    struct avail *block = (struct avail *)ptr - 1;
    while (block->kval < pool->kval_m) {
        struct avail *buddy = buddy_calc(pool, block);
        if (buddy->tag != BLOCK_AVAIL || buddy->kval != block->kval) {
            break;
        }

        // Remove buddy from the free list
        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;

        if (buddy < block) {
            block = buddy;
        }

        block->kval++;
    }

    block->tag = BLOCK_AVAIL;
    block->next = &pool->avail[block->kval];
    block->prev = pool->avail[block->kval].prev;
    pool->avail[block->kval].prev->next = block;
    pool->avail[block->kval].prev = block;
}

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