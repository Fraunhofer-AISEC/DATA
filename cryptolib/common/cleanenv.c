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
 * @file cleanenv.c
 * @brief Provides a clean execution environment.
 * @license This project is released under the GNU GPLv3+ License.
 * @author See AUTHORS file.
 * @version 0.2
 */

/***********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

/***********************************************************************/

void printme(char** args) {
  while(*args) {
    printf("%p: %s\n", *args, *args);
    args++;
  }
}

void help(char* arg0) {
  printf("%s <env-file> <prog> [args ...]\n\n", arg0);
  printf("Run <prog> with args in a clean environment, specified by <env-file>.\n");
  printf("<env-file> contains key-value pairs (KEY=VALUE) and is directly provided to <prog> via execve.\n");
}

/***********************************************************************/

char *setarch = "/usr/bin/setarch\0";
char *march = "x86_64\0";
char *disable_aslr = "-R\0";

/***********************************************************************/

int main(int argc, char** argv) {
  /* at least env file and program */
  if (argc < 3) {
    help(argv[0]);
    return -1;
  }

  /* init */
  int i;
  const size_t line_size = 1024;
  const size_t env_size = 256;
  char* execveargs[argc+1];
  size_t idx = 0;
  char* line = malloc(line_size);
  assert(line);
  char* newenv[env_size];
  memset(newenv, 0, env_size*sizeof(char*));

  /* get env file content */
  FILE* fh = fopen(argv[1], "r");
  if (!fh) {
    free(line);
    perror("cleanenv: fopen failed!");
    return (-1);
  }
  while (fgets(line, line_size, fh) != NULL) {
    /* make sure 0-termination exists */
    line[line_size-1] = '\0';
    /* delete last character, if newline '\n' */
    size_t len = strlen(line);
    if (line[len-1] == '\n') {
      line[len-1] = '\0';
    }
    newenv[idx++] = line;
    if (idx >= env_size) {
      for (i = 0; i < env_size; i++) {
        if (newenv[i] != NULL) {
          free(newenv[i]);
        }
      }
      fclose(fh);
      fprintf(stderr, "cleanenv: too many environment variables!");
      return (-2);
    }
    newenv[idx] = NULL;
    line = malloc(line_size);
    assert(line);
  }
  fclose(fh);

  /* build execve arguments */
  execveargs[0] = march;
  execveargs[1] = disable_aslr;
  for (i = 2; i < argc; i++) {
    execveargs[i] = argv[i];
  }
  execveargs[argc] = NULL;

  /* call execve */
  if (execve(setarch, execveargs, newenv)) {
    perror("cleanenv: execve failed");
    return -3;
  }
  return (0);
}

