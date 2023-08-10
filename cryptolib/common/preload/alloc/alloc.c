/************************************************************************
 * Copyright (C) 2017-2018 IAIK TU Graz and Fraunhofer AISEC
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 ***********************************************************************/

/**
 * @file alloc.c
 * @brief Simple wrapper for preloading allocation routines.
 * @license This project is released under the GNU GPLv3+ License.
 * @author See AUTHORS file.
 * @version 0.3
 */

/***********************************************************************/

/*
 * Hook allocation routines, inspired by
 * https://stackoverflow.com/questions/6083337/overriding-malloc-using-the-ld-preload-mechanism
 *
 * When instrumenting with IPOINT_AFTER, Intel pin detects function returns by
 * searching for 'ret' instructions in the function body. However, for
 * Ubuntu 16.04 glibc-2.23, calloc seems to do a jmp to another routine rather
 * than a 'ret' instruction. To still detect when calloc returns, we wrap each
 * allocation routine in a separate function that has a 'ret' instruction.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

static void *(*real_malloc)(size_t) = NULL;
static void *(*real_realloc)(void *, size_t) = NULL;
static void *(*real_calloc)(size_t, size_t) = NULL;
static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
static void *(*real_mremap)(void *, size_t, size_t, int, ...) = NULL;
static int (*real_munmap)(void *, size_t) = NULL;
static void (*real_free)(void *) = NULL;

static int alloc_init_pending = 0;

/* Load original allocation routines at first use */
static void alloc_init(void) {
    alloc_init_pending = 1;
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_mremap = dlsym(RTLD_NEXT, "mremap");
    real_munmap = dlsym(RTLD_NEXT, "munmap");
    real_free = dlsym(RTLD_NEXT, "free");
    if (!real_malloc || !real_realloc || !real_calloc ||
        !real_mremap || !real_munmap || !real_free) {
        fputs("alloc.so: Unable to hook allocation!", stderr);
        fputs(dlerror(), stderr);
        exit(1);
    } else {
        // fputs("alloc.so: Successfully hooked\n", stderr);
    }
    alloc_init_pending = 0;
}

#define ZALLOC_MAX 1024
static void *zalloc_list[ZALLOC_MAX];
static size_t zalloc_cnt = 0;

/* dlsym needs dynamic memory before we can resolve the real memory
 * allocator routines. To support this, we offer simple mmap-based
 * allocation during alloc_init_pending.
 * We support a max. of ZALLOC_MAX allocations.
 *
 * On the tested Ubuntu 16.04 with glibc-2.23, this happens only once.
 */
void *zalloc_internal(size_t size) {
    // fputs("alloc.so: zalloc_internal called", stderr);
    if (zalloc_cnt >= ZALLOC_MAX - 1) {
        fputs("alloc.so: Out of internal memory\n", stderr);
        return NULL;
    }
    /* Anonymous mapping ensures that pages are zero'd */
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (MAP_FAILED == ptr) {
        perror("alloc.so: zalloc_internal mmap failed\n");
        return NULL;
    }
    zalloc_list[zalloc_cnt++] = ptr; /* keep track for later calls to free */
    return ptr;
}

void free(void *ptr) {
    if (alloc_init_pending) {
        fputs("alloc.so: free internal\n", stderr);
        /* Ignore 'free' during initialization and ignore potential mem leaks
         * On the tested system, this did not happen
         */
        return;
    }
    if (!real_malloc) {
        alloc_init();
    }
    for (size_t i = 0; i < zalloc_cnt; i++) {
        if (zalloc_list[i] == ptr) {
            /* If dlsym cleans up its dynamic memory allocated with
             * zalloc_internal, we intercept and ignore it, as well as the
             * resulting mem leaks. On the tested system, this did not happen
             */
            return;
        }
    }
    real_free(ptr);
}

void *malloc(size_t size) {
    if (alloc_init_pending) {
        fputs("alloc.so: malloc internal\n", stderr);
        return zalloc_internal(size);
    }
    if (!real_malloc) {
        alloc_init();
    }
    void *result = real_malloc(size);
    // fprintf(stderr, "alloc.so: malloc(0x%zx) = %p\n", size, result);
    return result;
}

void *realloc(void *ptr, size_t size) {
    if (alloc_init_pending) {
        fputs("alloc.so: realloc internal\n", stderr);
        if (ptr) {
            fputs("alloc.so: realloc resizing not supported\n", stderr);
            exit(1);
        }
        return zalloc_internal(size);
    }
    if (!real_malloc) {
        alloc_init();
    }
    return real_realloc(ptr, size);
}

void *calloc(size_t nmemb, size_t size) {
    if (alloc_init_pending) {
        fputs("alloc.so: calloc internal\n", stderr);
        return zalloc_internal(nmemb * size);
    }
    if (!real_malloc) {
        alloc_init();
    }
    return real_calloc(nmemb, size);
}

void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ...) {
    if (alloc_init_pending) {
        fputs("alloc.so: mremap internal\n", stderr);
        if (old_address) {
            fputs("alloc.so: mremap resizing not supported\n", stderr);
            exit(1);
        }
        return zalloc_internal(old_size);
    }
    if (!real_malloc) {
        alloc_init();
    }
    return real_mremap(old_address, old_size, new_size, flags);
}

int munmap(void *addr, size_t length) {
    if (alloc_init_pending) {
        fputs("alloc.so: munmap internal\n", stderr);
        /* Ignore 'munmap' during initialization and ignore potential mem leaks
         * On the tested system, this did not happen
         */
        return -1;
    }
    if (!real_malloc) {
        alloc_init();
    }
    for (size_t i = 0; i < zalloc_cnt; i++) {
        if (zalloc_list[i] == addr) {
            /* If dlsym cleans up its dynamic memory allocated with
             * zalloc_internal, we intercept and ignore it, as well as the
             * resulting mem leaks. On the tested system, this did not happen
             */
            return -1;
        }
    }
    return real_munmap(addr, length);
}
