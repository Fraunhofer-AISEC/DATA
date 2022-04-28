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
 * @file dmt-utils.h
 * @brief Dynamic memory tracking helper functions.
 * @license This project is released under the GNU GPLv3+ License.
 * @author See AUTHORS file.
 * @version 0.3
 */

/***********************************************************************/

#include <stdlib.h>
#include <inttypes.h>

/***********************************************************************/

#define RANDRANGE(M,N) (M + (N - M) * (float)rand() / (float)RAND_MAX)
#define INVALIDPTR(p) (p == NULL || p == (void*)-1)

/***********************************************************************/

#define SMALL  RANDRANGE(16,1024)
#define MEDIUM RANDRANGE(1024,100*1024)
#define LARGE  RANDRANGE(100*1024,1*1024*1024)
#define HUGE   RANDRANGE(1*1024*1024,10*1024*1024)

/***********************************************************************/

/***
 * Allocate a new object with <size> bytes.
 * If <type> is zero, malloc is used. Otherwise,
 * mmap is used. If <alt> is non-zero, a slight
 * variant of the allocation call is used.
 *
 * @param size number of bytes to allocate
 * @param type 0: malloc, else: mmap
 * @param alt 0: standard call, else: alternative call
 * @return allocated object pointer
 */
void* dmt_allocate(size_t size, int type, int alt);

/***********************************************************************/

/***
 * Re-allocate an object to <newsize> bytes.
 * If <type> is zero, realloc is used. Otherwise,
 * mremap is used.
 *
 * @param obj object to reallocate
 * @param oldsize previous object size
 * @param newsize new number of bytes to allocate
 * @param type 0: realloc, else: mremap
 * @return re-allocated object pointer
 */
void* dmt_reallocate(void* obj, size_t oldsize, size_t newsize, int type);

/***********************************************************************/

/***
 * Free resources of an object.
 * If <type> is zero, free is used. Otherwise,
 * munmap is used.
 *
 * @param obj object to free
 * @param size allocation size in bytes
 * @param type 0: free, else: munmap
 * @return 0: success, else: error
 */
int dmt_deallocate(void* obj, size_t size, int type);

