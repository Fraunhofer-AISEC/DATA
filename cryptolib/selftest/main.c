#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>


const unsigned char permute[] = {
  0x76,0x63,0x37,0x8e,0xdd,0x6e,0xfd,0xc6,
  0xc8,0x3c,0x1f,0xf7,0xb0,0xdb,0xe0,0xf1
};

char state[16] = {0};

int main(int argc, char** argv) {

  printf("Hello!\n");
  if (argc != 2) {
    printf("Provide <key-file> as argument\n");
    return -1;
  }

  FILE* f = fopen(argv[1], "r");
  if (!f) {
    perror("Unable to open file");
    return -2;
  }

  volatile char result = 0;
  unsigned char value;
  unsigned char str[2];
  size_t repeat = 0;

  /* read key from file */
  while (fread(&str, 1, 2, f) == 2) {
    repeat++;
    unsigned char perm;

    /* read higher nibble of key byte */
    /* key-independent conversion from hex string to byte */
    value = (str[0] % 32 + 9) % 25;

    /* key-dependent data access */
    /* triggers H_pos(b), H_addr */
    /* expected leak stats: */
    /*   difference: 1 */
    /*   data leak generic: 1 */
    /*   data leak specific: 1 (key byte nibble high) */
    perm = permute[value];

    /* key-dependent branch */
    /* triggers H_addr */
    /* expected leak stats: */
    /*   difference = 1 */
    /*   control-flow leak generic = 1 */
    /*   control-flow leak specific = 2 (key byte MSB + nibble high) */
    if (value > 7) {
      result -= perm;
    } else {
      result += perm;
    }

    /* key-dependent branch and data access */
    /* triggers H_pos(a), H_pos(b), H_addr */
    /* expected leak stats: */
    /*   difference = 2 */
    /*   data leak generic = 1 */
    /*   data leak specific = 1 (key byte nibble high) */
    /*   control-flow leak generic = 1 */
    /*   control-flow leak specific = 2 (key byte MSB + nibble high) */
    if (value > 7) {
      state[value] = result;
    }
  }

  /* initialize random numbers */
  srand((unsigned int)getpid() + (unsigned int)value);

  /* randomized   */
  for (size_t i = 0; i < repeat; i++) {
    unsigned char perm;
    value = rand() % 16;

    /* key-independent data access */
    /* expected leak stats: */
    /*   difference = 1 */
    /*   data leak generic = 0 */
    /*   data leak specific = 0 */
    perm = permute[value];

    /* key-independent branch */
    /* expected leak stats: */
    /*   difference = 1 */
    /*   control-flow leak generic = 0 */
    /*   control-flow leak specific = 0 */
    if (value > 7) {
      result -= perm;
    } else {
      result += perm;
    }

    /* key-independent branch and data access */
    /* expected leak stats: */
    /*   difference = 2 */
    /*   data leak generic = 0 */
    /*   data leak specific = 0 */
    /*   control-flow leak generic = 0 */
    /*   control-flow leak specific = 0 */
    if (value > 7) {
      state[value] = result;
    }
  }

  fclose(f);
  return 0;
}
