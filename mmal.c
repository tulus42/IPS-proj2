// xhosti02

/**
 * Implementace My MALloc
 * Demonstracni priklad pro 1. ukol IPS/2018
 * Ales Smrcka
 */

#include "mmal.h"
#include <sys/mman.h> // mmap
#include <stdbool.h> // bool
#include <assert.h> // assert

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0xc20
#endif

#ifdef NDEBUG
/**
 * The structure header encapsulates data of a single memory block.
 *   ---+------+----------------------------+---
 *      |Header|DDD not_free DDDDD...free...|
 *   ---+------+-----------------+----------+---
 *             |-- Header.asize -|
 *             |-- Header.size -------------|
 */
typedef struct header Header;
struct header {

    /**
     * Pointer to the next header. Cyclic list. If there is no other block,
     * points to itself.
     */
    Header *next;

    /// size of the block
    size_t size;

    /**
     * Size of block in bytes allocated for program. asize=0 means the block 
     * is not used by a program.
     */
    size_t asize;
};

/**
 * The arena structure.
 *   /--- arena metadata
 *   |     /---- header of the first block
 *   v     v
 *   +-----+------+-----------------------------+
 *   |Arena|Header|.............................|
 *   +-----+------+-----------------------------+
 *
 *   |--------------- Arena.size ---------------|
 */
typedef struct arena Arena;
struct arena {

    /**
     * Pointer to the next arena. Single-linked list.
     */
    Arena *next;

    /// Arena size.
    size_t size;
};

#define PAGE_SIZE (128*1024)

#endif // NDEBUG

Arena *first_arena = NULL;

/**
 * Return size alligned to PAGE_SIZE
 */
static
size_t allign_page(size_t size)
{
    size = (size + (128*1024) - 1) / (128*1024) * (128*1024);
    return size;
}

/**
 * Allocate a new arena using mmap.
 * @param req_size requested size in bytes. Should be alligned to PAGE_SIZE.
 * @return pointer to a new arena, if successfull. NULL if error.
 * @pre req_size > sizeof(Arena) + sizeof(Header)
 */

/**
 *   +-----+------------------------------------+
 *   |Arena|....................................|
 *   +-----+------------------------------------+
 *
 *   |--------------- Arena.size ---------------|
 */
static
Arena *arena_alloc(size_t req_size)
{
    Arena* new_arena = NULL;
    
    assert(req_size > sizeof(Arena) + sizeof(Header));
    
    new_arena = (Arena*)mmap(NULL, (req_size), PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, -1, 0);
    if (new_arena == MAP_FAILED) {
        return NULL;
    }
    new_arena->size = req_size;

    return new_arena;
}

/**
 * Appends a new arena to the end of the arena list.
 * @param a     already allocated arena
 */
static
void arena_append(Arena *a)
{
    Arena* tmp;
    tmp = first_arena;

    if (first_arena == NULL) {
        first_arena = a;
    } else {
        while (tmp->next != NULL) {
            tmp = tmp->next;
        }
        tmp->next = a;
    }
}

/**
 * Header structure constructor (alone, not used block).
 * @param hdr       pointer to block metadata.
 * @param size      size of free block
 * @pre size > 0
 */
/**
 *   +-----+------+------------------------+----+
 *   | ... |Header|........................| ...|
 *   +-----+------+------------------------+----+
 *
 *                |-- Header.size ---------|
 */
static
void hdr_ctor(Header *hdr, size_t size)
{
    assert(size > 0);

    hdr->size = size;
    hdr->asize = 0;
    
}

/**
 * Checks if the given free block should be split in two separate blocks.
 * @param hdr       header of the free block
 * @param size      requested size of data
 * @return true if the block should be split
 * @pre hdr->asize == 0
 * @pre size > 0
 */
static
bool hdr_should_split(Header *hdr, size_t size)
{
    assert(hdr->asize == 0);
    assert(size > 0);
    
    if (2*(sizeof(Header))+size <= hdr->size) {
        return true;
    } else {
        return false;
    }
}

/**
 * Splits one block in two.
 * @param hdr       pointer to header of the big block
 * @param req_size  requested size of data in the (left) block.
 * @return pointer to the new (right) block header.
 * @pre   (hdr->size >= req_size + 2*sizeof(Header))
 */
/**
 * Before:        |---- hdr->size ---------|
 *
 *    -----+------+------------------------+----
 *         |Header|........................|
 *    -----+------+------------------------+----
 *            \----hdr->next---------------^
 */
/**
 * After:         |- req_size -|
 *
 *    -----+------+------------+------+----+----
 *     ... |Header|............|Header|....|
 *    -----+------+------------+------+----+----
 *             \---next--------^  \--next--^
 */
static
Header *hdr_split(Header *hdr, size_t req_size)
{
    assert((hdr->size >= req_size + 2*sizeof(Header)));

    char* tmp_hdr = (char*)&hdr[1] + req_size;

    Header *tmp = (Header*)tmp_hdr;


    hdr_ctor(tmp, req_size + sizeof(Header));

    if (hdr == hdr->next) {
        hdr->next = tmp;
        tmp->next = hdr;
    } else {
        tmp->next = hdr->next;
        hdr->next = tmp;
    }
        tmp->size = hdr->size - (req_size + sizeof(Header));
        tmp->asize = 0;

        hdr->size = 0;
        hdr->asize = req_size;
    
    return tmp;
}

/**
 * Detect if two adjacent blocks could be merged.
 * @param left      left block
 * @param right     right block
 * @return true if two block are free and adjacent in the same arena.
 * @pre left->next == right
 * @pre left != right
 */
static
bool hdr_can_merge(Header *left, Header *right)
{
    assert(left->next == right);
    assert(left != right);

    if (left->asize == 0 && right->asize == 0) {
        Header* tmp;
        tmp = (Header*)((char*)(left)+ sizeof(Header) + left->size); 
        if (tmp == right) {
            return true;
        }
    }
    
    return false;
}

/**
 * Merge two adjacent free blocks.
 * @param left      left block
 * @param right     right block
 * @pre left->next == right
 * @pre left != right
 */
static
void hdr_merge(Header *left, Header *right)
{
    assert(left->next == right);
    assert(left != right);

    if (hdr_can_merge(left, right) == true) {
        left->size = left->size + right->size + sizeof(Header);
        left->next = right->next;
    }
}

/**
 * Finds the first free block that fits to the requested size.
 * @param size      requested size
 * @return pointer to the header of the block or NULL if no block is available.
 * @pre size > 0
 */
static
Header *first_fit(size_t size)
{
    assert(size > 0);

    Header* tmp = &first_arena[1];

    if (tmp->size < size) {
        tmp = tmp->next;

        while (tmp->size < size + 2*sizeof(Header) && tmp != &first_arena[1]) {
            tmp = tmp->next;
        }
    }
    
    if (tmp->size >= size) {
        return tmp;
    } else {
        return NULL;
    }
}

/**
 * Search the header which is the predecessor to the hdr. Note that if 
 * @param hdr       successor of the search header
 * @return pointer to predecessor, hdr if there is just one header.
 * @pre first_arena != NULL
 * @post predecessor->next == hdr
 */
static
Header *hdr_get_prev(Header *hdr)
{
    assert(first_arena != NULL);

    Header* tmp = hdr;

    while (tmp->next != hdr) {
        tmp = tmp->next;
    }
    return tmp;

}

/**
 * Allocate memory. Use first-fit search of available block.
 * @param size      requested size for program
 * @return pointer to allocated data or NULL if error or size = 0.
 */
void *mmalloc(size_t size)
{
    Header* first_hdr = NULL;
    Header* new_hdr;
    Header* tmp;
    Header* fitted_hdr;

    Arena* new_arena;

    if (size == 0) {
        return NULL;
    }
    
    if (first_arena == NULL) {
        

        first_arena = arena_alloc(allign_page(size+2*sizeof(Header)+sizeof(Arena)));
        if (first_arena == NULL) {
            return NULL;
        }
        first_hdr = &first_arena[1];
        hdr_ctor((first_hdr), first_arena->size - sizeof(Header));
        first_hdr->next = first_hdr;

        new_hdr = hdr_split(first_hdr, size);

        tmp = (Header*)((char*)(new_hdr) - size);
        return tmp;

    } else {
        fitted_hdr = first_fit(size);
            //ak sa este zmesti do aktualnej areny
        if (fitted_hdr != NULL) {
            new_hdr = hdr_split(fitted_hdr, size);

            tmp = (Header*)((char*)(new_hdr) - size);
            return tmp;

        } else {
            // ak potrebujeme novu arenu
            Header* last_hdr = &first_arena[1];
            Header* new_first_hdr;

            new_arena = arena_alloc(allign_page(size+2*sizeof(Header)+sizeof(Arena)));
            if (new_arena == NULL) {
                return NULL;
            }
            arena_append(new_arena);

            new_first_hdr = &new_arena[1];
            hdr_ctor((new_first_hdr), new_arena->size - sizeof(Header));
            
            

            while (last_hdr->next != &first_arena[1]) {
                last_hdr = last_hdr->next;
            }
            last_hdr->next = new_first_hdr;

            new_hdr = hdr_split(new_first_hdr, size);
            new_hdr->next = &first_arena[1];

            tmp = (Header*)((char*)(new_hdr) - size);
            return tmp;
        }
    }    



    return NULL;

}

/**
 * Free memory block.
 * @param ptr       pointer to previously allocated data
 * @pre ptr != NULL
 */
void mfree(void *ptr)
{
    assert(ptr != NULL);
    
    Header* hdr;
    hdr = (Header*)(ptr-24);

    hdr->size = hdr->asize + hdr->size;
    hdr->asize = 0;

    if (hdr == hdr->next) {
        // len odstranime hdr
        
    } else
    if (hdr == &first_arena[1]) {
        // hdr je prvy header
        if (hdr_can_merge(hdr, hdr->next) == true) {
            hdr_merge(hdr, hdr->next);
        } 
    } else 
    if (hdr->next == &first_arena[1]) {
        // hdr je posledny header
        Header* prev_hdr = hdr_get_prev(hdr);
        if (hdr_can_merge(prev_hdr, hdr) == true) {
            hdr_merge(prev_hdr, hdr);
        } 
    } else {
        // hdr je niekde v strede -> kontrola next ja prev
        Header* prev_hdr = hdr_get_prev(hdr);
        bool left;
        bool right;

        left = hdr_can_merge(prev_hdr, hdr);
        right = hdr_can_merge(hdr, hdr->next);
        if (right == true) {
            hdr_merge(hdr, hdr->next);
        }
        if (left == true) {
            hdr_merge(prev_hdr, hdr);
        }
        /*       
        if (left == false && right == false) {
            hdr->size = hdr->asize + hdr->size;
            hdr->asize = 0;
        }
        */
    }
    
    


}

/**
 * Reallocate previously allocated block.
 * @param ptr       pointer to previously allocated data
 * @param size      a new requested size. Size can be greater, equal, or less
 * then size of previously allocated block.
 * @return pointer to reallocated space or NULL if size equals to 0.
 */
void *mrealloc(void *ptr, size_t size)
{
    Header* hdr_ptr = (Header*)(ptr-24);
    void* res_ptr;
    res_ptr = mmalloc(size);
    int msize;

    if (hdr_ptr->asize > size) {
        msize = size;
    } else {
        msize = hdr_ptr->asize;
    }

    res_ptr = memcpy(res_ptr, ptr, msize);

    mfree(ptr);
    
    return res_ptr;
}
