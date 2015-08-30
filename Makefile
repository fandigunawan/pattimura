IDIR =.
CC=gcc
CFLAGS=-I$(IDIR)

ODIR=.

_DEPS = pattimura.h utils.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = pattimura.o utils.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all : example vector

example: example.o $(OBJ)
	gcc -o $@ $^ $(CFLAGS)
	
vector: vector.o $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o example vector