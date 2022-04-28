#-------------------------------------------------------------------------
# NMAKE-Makefile
#-------------------------------------------------------------------------
PROJ=dynamic memory tracking example programs
UTIL1=dmt-utils
PROG1=dmt-realloc
PROG2=dmt-access

#-------------------------------------------------------------------------
# Compiler-Flags General
#-------------------------------------------------------------------------
CC := gcc
CFLAGS := -g -O0 -Wall -Werror
LDD := ldd
LIBS :=
INCLUDE := -I.
ifeq ($(MAKECMDGOALS),debug)
  CFLAGS += -DDEBUG
endif

#-------------------------------------------------------------------------
# Objects and Output
#-------------------------------------------------------------------------
DIR_OUTPUT := bin
DIR_UTILS := $(DIR_OUTPUT)/utils
DIR_PROGS := $(DIR_OUTPUT)/programs
UTILS := $(DIR_UTILS)/$(UTIL1)
UTILS_OBJ := $(patsubst %, %.o, $(UTILS))
PROGRAMS := $(DIR_PROGS)/$(PROG1) $(DIR_PROGS)/$(PROG2)

#-------------------------------------------------------------------------
# Main-Targets
#-------------------------------------------------------------------------
.PHONY: all help

all: output $(UTILS) $(PROGRAMS)
debug: all

output:
	@if [ -d $(DIR_OUTPUT) ]; then \
		echo "dir $(DIR_OUTPUT) already exists."; \
	else \
		mkdir -p $(DIR_UTILS); \
		mkdir -p $(DIR_PROGS); \
	fi

clean:
	-$(RM) -r $(DIR_OUTPUT)

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "make [all]"
	@echo "make [help|clean]"
	@echo
	@echo "Targets  : help    - Shows this text."
	@echo "           all     - Compiles the project."
	@echo "           debug   - Enable debug output."
	@echo "           clean   - Cleans up output files."
	@echo

#-------------------------------------------------------------------------
# Sub-Targets
#-------------------------------------------------------------------------

# build utils
$(DIR_UTILS)/%: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@.o

# build programs
$(DIR_PROGS)/%: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@.o
	$(CC) $(INCLUDE) -o $@ $@.o $(UTILS_OBJ) $(LIBS)
	$(LDD) $@

