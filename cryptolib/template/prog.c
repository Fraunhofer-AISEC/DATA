#include <stdio.h>

int main(int argc, const char** argv) {
  if (argc != 2) {
    printf("Provide key file as first argument!\n");
    return -1;
  }

  printf("Leaky hex conversion\n");
  FILE* f = fopen(argv[1], "r");
  
  char buffer;
  while (fread(&buffer, 1, sizeof(buffer), f) > 0) {
    printf("%02x", buffer);
  }
  printf("\nBye!\n");
  fclose(f);
  return 0;
}
