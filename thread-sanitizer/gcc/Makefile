OBJS=tsan.o tree-tsan.o
CFLAGS+=-I$(GCC_DIR) -DIN_GCC=1 -fPIC -Wall -std=gnu89
OUT=libtsan.so

ifeq ($(DEBUG), )
	CFLAGS+=-O3 -DNDEBUG
else
	CFLAGS+=-g -D_DEBUG
endif

all: $(OBJS)
	$(CC) $(OBJS) -shared -o $(OUT)

clean:
	rm -f *.o $(OUT)

