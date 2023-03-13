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
 * @file dmt-access.c
 * @brief Dynamic memory tracking simple access selftest.
 * @license This project is released under the GNU GPLv3+ License.
 * @author See AUTHORS file.
 * @version 0.3
 */

/***********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include "dmt-utils.h"

/***********************************************************************/

#define LARGE_INIT 524288

/***********************************************************************/

void help();

/***********************************************************************/

uint16_t ALLOC_TYPE = 0;
uint16_t USE_ALTERNATIVE = 0;

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
  int err = 1;
  uint8_t key = 0;
  FILE *kfile = NULL;
  unsigned char str[2];
  void *obj = NULL;
  size_t objsize = 0;
  char lookup = 0;

  /* check args */
  if (argc != 4) {
    help();
    return (1);
  }

  /* get cmdline args */
  sscanf(argv[1], "%hu", &ALLOC_TYPE);
  sscanf(argv[2], "%hu", &USE_ALTERNATIVE);

  /* read key */
  kfile = fopen(argv[3], "r");
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

  /* allocate object */
  objsize = LARGE_INIT;
  obj = dmt_allocate(objsize, ALLOC_TYPE, USE_ALTERNATIVE);
  if (INVALIDPTR(obj)) {
    printf("[Error] Unable to allocate object!\n");
    return (1);
  }

  /* debug info */
#ifdef DEBUG
  printf("Max rand() value: %u\n", RAND_MAX);
  printf("Allocate type: %s\n", (ALLOC_TYPE ? "mmap" : "malloc"));
  printf("Use alternative: %s\n", (USE_ALTERNATIVE ? "yes" : "no"));
  printf("Key nibble: %x\n", key);
  printf("Object size: %zu\n", objsize);
  printf("Object address: %0*"PRIxPTR"\n", (int)(sizeof(void*) * 2), (uintptr_t)obj);
#endif

  /* key-dependent data access */
  /* triggers H_pos(b), H_addr */
  /* expected leak stats: */
  /*   difference: 1 */
  /*   data leak generic: 1 */
  /*   data leak specific: 1 (key byte nibble high) */
  lookup = ((uint8_t*)obj)[key];
  fprintf(stdin, "%d\n", lookup);

  /* key-independent data access */
  /* expected leak stats: */
  /*   difference = 1 */
  /*   data leak generic = 0 */
  /*   data leak specific = 0 */
  key = rand() % 16;
  lookup = ((uint8_t*)obj)[key];
  fprintf(stdin, "%d\n", lookup);

  /* deallocate */
  err = dmt_deallocate(obj, objsize, ALLOC_TYPE);

  /* done */
  return (err);
}

/***********************************************************************/

/***
 * Print help text.
 */
void help()
{
  printf("Usage:\n");
  printf("  dmt-access <type> <alt> <key>\n\n");
  printf("  <type> ....... 0: malloc & co, else: mmap & co\n");
  printf("  <alt> ........ 0: standard (malloc,mmap private), else: alternative (calloc,mmap shared)\n");
  printf("  <key file> ... file containing secret key byte as hex string\n");
}

