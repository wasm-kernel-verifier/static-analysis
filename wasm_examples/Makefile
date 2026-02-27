CC := clang
TARGET := wasm32-unknown-none
CFLAGS := -ffreestanding -nostdlib --target=$(TARGET) -g3 -O3 -fno-inline-functions
CFLAGS += -Wl,--no-entry -Wl,--export-all
WASMFLAGS := -mno-fp16 -mno-extended-const -mno-exception-handling -mno-atomics -mno-reference-types -mno-relaxed-simd -mno-simd128 -mno-wide-arithmetic

WASMPROGS := $(patsubst %.c,%.wasm,$(wildcard *.c))

.PHONY: all clean
all: $(WASMPROGS)
clean:
	rm -f $(WASMPROGS)

%.wasm: %.c
	$(CC) $(CFLAGS) $(WASMFLAGS) $^ -o $@
