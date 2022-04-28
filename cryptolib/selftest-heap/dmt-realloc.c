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
 * @file dmt-realloc.c
 * @brief Dynamic memory tracking re-allocation selftest.
 * @license This project is released under the GNU GPLv3+ License.
 * @author See AUTHORS file.
 * @version 0.3
 */

/***********************************************************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <malloc.h>
#include "dmt-utils.h"

/***********************************************************************/

#define MIN_OBJ_NUMBER 13
#define SMALL_INIT  512
#define MEDIUM_INIT 49152
#define LARGE_INIT  524288
#define HUGE_INIT   5242880

/***********************************************************************/

void help();
void* allocate(size_t size, int id);
void* reallocate(void* obj, size_t oldsize, size_t newsize, int id);
int deallocate(void* obj, size_t size, int id);
int fill(uint16_t number, void** obj);
int change(uint16_t number, void** obj);
int readaddr(void** addr, uint16_t number);
int test(uint16_t number, uint8_t key);
#ifdef DEBUG
void printstats(uint16_t number, void** obj);
void printaddr(uint16_t number, void** addr);
#endif

/***********************************************************************/

uint16_t ALLOC_TYPE = 0;
uint16_t USE_ALTERNATIVE = 0;
uint16_t LEAKAGE_POINTS = 0;
size_t* ALLOC_SIZES = NULL;
uint8_t* ALLOC_CHANGED = NULL;

/***********************************************************************/

uint8_t DUMMY_OBJ = 0;

/***********************************************************************/

/***
 * Main function.
 *
 * @param argc number of command line arguments
 * @param argv command line arguments
 * @return 0=success, else=error
 */
int main(int argc, char **argv)
{
  /* init */
  int err;
  uint16_t number;
  uint8_t key;
  unsigned char str[2];
  FILE *kfile = NULL;

  /* check args */
  if (argc != 6) {
    help();
    return (1);
  }

  /* get cmdline args */
  sscanf(argv[1], "%hu",  &ALLOC_TYPE);
  sscanf(argv[2], "%hu",  &USE_ALTERNATIVE);
  sscanf(argv[3], "%hu",  &LEAKAGE_POINTS);
  sscanf(argv[4], "%hu",  &number);

  /* read key */
  kfile = fopen(argv[5], "r");
  if (!kfile) {
    printf("[Error] Unable to open key file!\n");
    return (1);
  }
  if (fread(&str, 1, 2, kfile) != 2) {
    printf("[Error] Unable to read key file!\n");
    return (1);
  }
  key = (str[0] % 32 + 9) % 25;
  fclose(kfile);

  /* ini rnd */
  srand(getpid() + time(NULL));
#ifdef DEBUG
  printf("Max rand() value: %u\n", RAND_MAX);
  printf("Allocate type: %s\n", (ALLOC_TYPE ? "mmap" : "malloc"));
  printf("Use alternative: %s\n", (USE_ALTERNATIVE ? "yes" : "no"));
  printf("Leakage points: %s\n", (LEAKAGE_POINTS ? "2" : "1"));
  printf("Number of objects: %u\n", number);
  printf("Key nibble: %x\n", key);
#endif

  /* sanity check */
  if (number < MIN_OBJ_NUMBER) {
    printf("[Error] Number of objects too small. Please use %u or above.\n", MIN_OBJ_NUMBER);
    return (1);
  }

  /* test */
  err = test(number, key);

  /* done */
  return (err);
}

/***********************************************************************/

/***
 * Allocate a new object with <size> bytes.
 * If <USE_ALTERNATIVE> is non-zero, the
 * alternative will be used (e.g. calloc or
 * mmap shared).
 *
 * @param size number of bytes to allocate
 * @param id object id
 * @return allocated object pointer
 */
void* allocate(size_t size, int id)
{
  /* init */
  void* obj = NULL;

  /* allocate */
  obj = dmt_allocate(size, ALLOC_TYPE, USE_ALTERNATIVE);
  if (INVALIDPTR(obj)) { return(obj); }

  /* keep record */
  if (id >= 0) {
    ALLOC_SIZES[id] = size;
    ALLOC_CHANGED[id] = 0;
  }

  /* done */
  return (obj);
}

/***
 * Re-allocate an object to <newsize> bytes.
 *
 * @param obj object to reallocate
 * @param oldsize previous object size
 * @param newsize new number of bytes to allocate
 * @param id object id
 * @return allocated object pointer
 */
void* reallocate(void* obj, size_t oldsize, size_t newsize, int id)
{
  /* init */
  void* objnew = NULL;

  /* re-allocate */
  objnew = dmt_reallocate(obj, oldsize, newsize, ALLOC_TYPE);
  if (INVALIDPTR(objnew)) { return(objnew); }

  /* keep record */
  if (id >= 0) {
    ALLOC_SIZES[id] = newsize;
    if (objnew != obj) {
      ALLOC_CHANGED[id] = 1;
    }
  }

  /* done */
  return (objnew);
}

/***
 * Free resources of an object.
 *
 * @param obj object to free
 * @param size allocation size in bytes
 * @param id object id
 * @return 0: success, else: error
 */
int deallocate(void* obj, size_t size, int id)
{
  /* init */
  int res = 0;

  /* free */
  res = dmt_deallocate(obj, size, ALLOC_TYPE);

  /* clear record */
  if (id >= 0) {
    ALLOC_SIZES[id] = 0;
    ALLOC_CHANGED[id] = 0;
  }

  /* done */
  return (res);
}

/***********************************************************************/

/***
 * Fill an array with objects of different sizes:
 *   50% ... <   1kB
 *   20% ... < 100kB
 *   22% ... <   1MB
 *    8% ... <  10MB
 *
 * @param number number of objects to create
 * @param obj array to store objects in
 * @return 0: success, else: error
 */
int fill(uint16_t number, void** obj)
{
  /* init */
  int i;
  int huge = number * 0.08;
  int large = number * 0.22;
  int medium = number * 0.20;
  int small = (number - huge - large - medium);

  /* debug */
#ifdef DEBUG
  printf("*******************************\n");
  printf("Allocating:\n");
  printf("  Small:  %d\n", small);
  printf("  Medium: %d\n", medium);
  printf("  Large:  %d\n", large);
  printf("  Huge:   %d\n", huge);
#endif

  /* fill */
  for (i = 0; i < small; i++) {
    obj[i] = allocate(SMALL_INIT, i);
    if (INVALIDPTR(obj[i])) {
      printf("[Error] Could not allocate small object #%d!\n", i);
      return (1);
    }
  }
  for (; i < (small+medium); i++) {
    obj[i] = allocate(MEDIUM_INIT, i);
    if (INVALIDPTR(obj[i])) {
      printf("[Error] Could not allocate medium object #%d!\n", i-small);
      return (1);
    }
  }
  for (; i < (small+medium+large); i++) {
    obj[i] = allocate(LARGE_INIT, i);
    if (INVALIDPTR(obj[i])) {
      printf("[Error] Could not allocate large object #%d!\n", i-small-medium);
      return (1);
    }
  }
  for (; i < (small+medium+large+huge); i++) {
    obj[i] = allocate(HUGE_INIT, i);
    if (INVALIDPTR(obj[i])) {
      printf("[Error] Could not allocate huge object #%d!\n", i-small-medium-large);
      return (1);
    }
  }

  /* done */
  return (0);
}

/***********************************************************************/

/***
 * Change the size of objects within an array:
 *   50% ... <   1kB
 *   20% ... < 100kB
 *   22% ... <   1MB
 *    8% ... <  10MB
 *
 * @param number number of objects to change
 * @param obj array containing objects
 * @return 0: success, else: error
 */
int change(uint16_t number, void** obj)
{
  /* init */
  int i,c,p;
  int huge = number * 0.08;
  int large = number * 0.22;
  int medium = number * 0.20;
  int small = (number - huge - large - medium);

  /* change */
  for (i = 0; i < number;) {
    c = rand() % 4;
    p = 0;
    switch (c) {
      case 0:
        if (small > 0) {
          small--;
          obj[i] = reallocate(obj[i], ALLOC_SIZES[i], SMALL, i);
          p = 1;
        }
        break;
      case 1:
        if (medium > 0) {
          medium--;
          obj[i] = reallocate(obj[i], ALLOC_SIZES[i], MEDIUM, i);
          p = 1;
        }
        break;
      case 2:
        if (large > 0) {
          large--;
          obj[i] = reallocate(obj[i], ALLOC_SIZES[i], LARGE, i);
          p = 1;
        }
        break;
      case 3:
        if (huge > 0) {
          huge--;
          obj[i] = reallocate(obj[i], ALLOC_SIZES[i], HUGE, i);
          p = 1;
        }
        break;
    }
    if (INVALIDPTR(obj[i])) {
      printf("[Error] Could not reallocate object #%d!\n", i);
      return (1);
    }
    if (p) {i++;}
  }

  /* done */
  return (0);
}

/***********************************************************************/

/***
 * Read from the addresses in the array.
 *
 * @param addr array containing addresses
 * @param number number of addresses
 * @return helper variable
 */
int readaddr(void** addr, uint16_t number)
{
  int i,tmp;
  tmp = 1;
  for (i = 0; i < number; i++) {
    tmp ^= ((uint8_t*)addr[i])[0];
  }
  return (tmp);
}

/***********************************************************************/

#ifdef DEBUG
/***
 * Print statistics of malloc and the objects
 * contained in the given array.
 *
 * @param number number of objects
 * @param obj array containing objects
 */
void printstats(uint16_t number, void** obj)
{
  /* total memory */
  struct mallinfo mi = mallinfo();
  printf("*******************************\n");
  printf("Allocated bytes: %d\n", mi.arena);

  /* objects entries */
  int i;
  for (i = 0; i < number; i++) {
    printf("  %*d: %*zu -- %s\n", 5, i, 10, ALLOC_SIZES[i], (ALLOC_CHANGED[i] ? "changed" : "_"));
  }
}
#endif

/***********************************************************************/

#ifdef DEBUG
/***
 * Print the addresses contained in
 * the given array.
 *
 * @param number number of objects
 * @param addr array containing addresses
 */
void printaddr(uint16_t number, void** addr)
{
  printf("*******************************\n");
  printf("Addresses:\n");
  int i;
  for (i = 0; i < number; i++) {
    printf("  %0*"PRIxPTR"\n", (int)(sizeof(void*) * 2), (uintptr_t)addr[i]);
  }
}
#endif

/***********************************************************************/

/***
 * Creates <number> memory objects of sizes between
 * few bytes to several megabytes. The objects will
 * be resized once.
 *
 * @param number number of memory objects
 * @param key secret key byte
 * @return 0: success, else: error
 */
int test(uint16_t number, uint8_t key)
{
  /* init */
  int i,j;
  int err = 1;
  void** objects = NULL;
  void** addr_before = NULL;
  void** addr_after = NULL;
  void** addr_current = NULL;

  /* create helper structures */
  ALLOC_SIZES = allocate(number * sizeof(size_t), -1);
  if (INVALIDPTR(ALLOC_SIZES)) {
    printf("[Error] Could not allocate size array!\n");
    goto cleanup;
  }
  ALLOC_CHANGED = allocate(number * sizeof(uint8_t), -1);
  if (INVALIDPTR(ALLOC_CHANGED)) {
    printf("[Error] Could not allocate change array!\n");
    goto cleanup;
  }
  addr_before = allocate(number * sizeof(void*), -1);
  if (INVALIDPTR(addr_before)) {
    printf("[Error] Could not allocate address array 'before'!\n");
    goto cleanup;
  }
  addr_after = allocate(number * sizeof(void*), -1);
  if (INVALIDPTR(addr_after)) {
    printf("[Error] Could not allocate address array 'after'!\n");
    goto cleanup;
  }

  /* create objects */
  objects = allocate(number * sizeof(void*), -1);
  if (INVALIDPTR(objects)) {
    printf("[Error] Could not allocate object array!\n");
    goto cleanup;
  }
  if (fill(number, objects)) {
    printf("[Error] Could not fill object array!\n");
    goto cleanup;
  }
#ifdef DEBUG
  printstats(number, objects);
#endif

  /* fill address array */
  for (i = 0; i < number; i++) {
    if (rand() & 0x1) {
      addr_before[i] = (void*)&DUMMY_OBJ;
    } else {
      addr_before[i] = (void*)((uint8_t*)(objects[i]) + key);
    }
  }
#ifdef DEBUG
  printaddr(number, addr_before);
#endif

  /* two leakage points */
  if (LEAKAGE_POINTS) {
    /* access objects */
    fprintf(stdin, "%d\n", readaddr(addr_before, number));

    /* realloc objects */
    if (change(number, objects)) {
      printf("[Error] Could not re-allocate objects!\n");
      goto cleanup;
    }
#ifdef DEBUG
    printstats(number, objects);
#endif

    /* fill address array */
    for (i = 0; i < number; i++) {
      if (addr_before[i] != (void*)&DUMMY_OBJ) {
        addr_after[i] = (void*)&DUMMY_OBJ;
      } else {
        addr_after[i] = (void*)((uint8_t*)(objects[i]) + key);
      }
    }
#ifdef DEBUG
    printaddr(number, addr_after);
#endif

    /* access objects */
    fprintf(stdin, "%d\n", readaddr(addr_after, number));
  }
  /* one leakage point */
  else {
    addr_current = addr_before;
    for (j = 0; j < 2; j++) {
      /* access objects */
      fprintf(stdin, "%d\n", readaddr(addr_current, number));
      if (j == 1) { break; }

      /* realloc objects */
      if (change(number, objects)) {
        printf("[Error] Could not re-allocate objects!\n");
        goto cleanup;
      }
#ifdef DEBUG
      printstats(number, objects);
#endif

      /* fill address array */
      for (i = 0; i < number; i++) {
        if (addr_before[i] != (void*)&DUMMY_OBJ) {
          addr_after[i] = (void*)&DUMMY_OBJ;
        } else {
          addr_after[i] = (void*)((uint8_t*)(objects[i]) + key);
        }
      }
#ifdef DEBUG
      printaddr(number, addr_after);
#endif
      addr_current = addr_after;
    }
    addr_current = NULL;
  }

  /* done */
  err = 0;
cleanup:
  if (!INVALIDPTR(objects)) {
    for (i = 0; i < number; i++) {
      if (!INVALIDPTR(objects[i])) {
        deallocate(objects[i], ALLOC_SIZES[i], i);
        objects[i] = NULL;
      }
    }
    deallocate(objects, number * sizeof(void*), -1);
  }
  if (!INVALIDPTR(ALLOC_SIZES)) {
    deallocate(ALLOC_SIZES, number * sizeof(size_t), -1);
  }
  if (!INVALIDPTR(ALLOC_CHANGED)) {
    deallocate(ALLOC_CHANGED, number * sizeof(uint8_t), -1);
  }
  if (!INVALIDPTR(addr_before)) {
    deallocate(addr_before, number * sizeof(void*), -1);
  }
  if (!INVALIDPTR(addr_after)) {
    deallocate(addr_after, number * sizeof(void*), -1);
  }
  return (err);
}

/***********************************************************************/

/***
 * Print help text.
 */
void help()
{
  printf("Usage:\n");
  printf("  dmt-realloc <type> <alt> <lpoint> <number> <key>\n\n");
  printf("  <type> ....... 0: malloc & co, else: mmap & co\n");
  printf("  <alt> ........ 0: standard (malloc,mmap private), else: alternative (calloc,mmap shared)\n");
  printf("  <lpoint> ..... 0: one leakage point, else: two leakage points\n");
  printf("  <number> ..... # of objects to create, 16-bit uint\n");
  printf("  <key file> ... file containing secret key byte as hex string\n");
}

