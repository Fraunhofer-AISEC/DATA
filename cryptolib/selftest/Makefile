#------------------------------------------------------------------------
# Settings
#------------------------------------------------------------------------

# Project Name
PROJ := DATA - <Library under test>

#------------------------------------------------------------------------
# Targets
#------------------------------------------------------------------------
.PHONY: all clean

all:
	$(CC) -g -O0 main.c -o main

clean:
	rm -f main

help:
	@echo
	@echo "$(PROJ)"
	@echo
	@echo "  make [all] ............. Prepare and/or compile."
	@echo "  make help .............. Show this text."
	@echo "  make clean ............. Clean up."
	@echo

