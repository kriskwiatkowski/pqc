# This Makefile can be used with GNU Make or BSD Make

LIB=libcommon.a
HEADERS= fips202.h aes.h sha2.h randombytes.h sp800-185.h nistseedexpander.h cpucycles.h speed_print.h
OBJECTS= fips202.o aes.o sha2.o randombytes.o sp800-185.o nistseedexpander.o cpucycles.o speed_print.o

CFLAGS=-O3 -march=native -mtune=native -flto -mavx2 -maes -mbmi2 -Wall -Wextra -Wpedantic -Wvla -Wredundant-decls -Wmissing-prototypes -std=gnu99 $(EXTRAFLAGS)

all: $(LIB)

%.o: %.s $(HEADERS)
	$(AS) -o $@ $<

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJECTS)
	$(AR) -r $@ $(OBJECTS)

clean:
	$(RM) $(OBJECTS)
	$(RM) $(LIB)
