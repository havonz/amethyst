CC = $(shell xcrun --sdk iphoneos --find clang)
STRIP = $(shell xcrun --sdk iphoneos --find strip)
SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
OBJCOPY = $(shell which llvm-objcopy)
LDID = $(shell which ldid)

CFLAGS := -I./include -isysroot $(SDK) -mios-version-min=12.0 -arch arm64e -arch arm64 \
	-Werror -Wall -Wno-unused-variable -Wno-unused-function -fvisibility=hidden -fvisibility-inlines-hidden

LDFLAGS := -L$(SDK)/usr/lib -lc -lSystem -lcompression -framework CoreFoundation \
	-Wl,-sectcreate,__DATA,__arm64_shc,./shc/arm64.bin

SRC = $(wildcard src/*.c) $(wildcard src/*.s)

shellcode:
	$(CC) -arch arm64 -c shc/arm64.s -o shc/arm64.o
	$(OBJCOPY) --dump-section=__TEXT,__text=shc/arm64.bin shc/arm64.o

_all: $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o jbutil $^
	$(STRIP) -x jbutil
	$(LDID) -Sents.xml jbutil

all: shellcode _all

clean:
	@rm -rf jbutil
	@rm -rf jbutil.dSYM
	@rm -rf *.o
