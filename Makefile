IDIR =.
CC=gcc
CFLAGS=-I$(IDIR)

ODIR=.

_DEPS = pattimura.h utils.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = example.o pattimura.o utils.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

example: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)
	
all : example

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o example