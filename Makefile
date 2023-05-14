IDIR =./src
CC=gcc
CFLAGS=-I$(IDIR)

ODIR=obj

LIBS=-lnfc

_DEPS = crapto1.h bucketsort.h mifare.h parity.h common.h nfc-utils.h mfkey.h 
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = nfc-super.o nfc-utils.o mfkey.o crapto1.o bucketsort.o crypto1.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

nfc-super: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$(ODIR)/%.o: $(IDIR)/%.c $(DEPS) | $(ODIR)
	$(CC) -c -o $@ $< $(CFLAGS)
	
$(ODIR):
	mkdir -p $@

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o

