CC = clang

CFLAGS = -Os -Wall -Wextra -pedantic

WASM_FLAGS = --target=wasm32 -nostdlib -ffreestanding -nobuiltininc -Wl,--no-entry

WASM_VM_EXTRA_FLAGS = -mnontrapping-fptoint -mbulk-memory -msign-ext -msimd128 -mtail-call -mreference-types -matomics -mmultivalue -Xclang -target-abi -Xclang experimental-mv

MVP_CFLAGS = $(shell pkg-config --cflags stdlea-mvp)
MVP_LIBS   = $(shell pkg-config --libs stdlea-mvp)
VM_CFLAGS  = $(shell pkg-config --cflags stdlea-vm)
VM_LIBS    = $(shell pkg-config --libs stdlea-vm)
TEST_CFLAGS = $(shell pkg-config --cflags stdlea)
TEST_LIBS   = $(shell pkg-config --libs stdlea)

ENCODER_SRC = cte.c encoder.c
DECODER_SRC = cte.c decoder.c
TEST_SRC    = test.c

ENCODER_MVP = encoder.mvp.wasm
DECODER_MVP = decoder.mvp.wasm
ENCODER_VM  = encoder.vm.wasm
DECODER_VM  = decoder.vm.wasm
TEST_TARGET = test

.PHONY: all clean mvp vm test_target

all: $(ENCODER_MVP) $(DECODER_MVP) $(ENCODER_VM) $(DECODER_VM) $(TEST_TARGET)

$(ENCODER_MVP): $(ENCODER_SRC) encoder.h cte.h
	@echo "Building MVP Encoder: $@"
	$(CC) $(WASM_FLAGS) $(CFLAGS) $(MVP_CFLAGS) $(ENCODER_SRC) $(MVP_LIBS) -o $@

$(DECODER_MVP): $(DECODER_SRC) decoder.h cte.h
	@echo "Building MVP Decoder: $@"
	$(CC) $(WASM_FLAGS) $(CFLAGS) $(MVP_CFLAGS) $(DECODER_SRC) $(MVP_LIBS) -o $@

$(ENCODER_VM): $(ENCODER_SRC) encoder.h cte.h
	@echo "Building VM Encoder: $@"
	$(CC) $(WASM_FLAGS) $(CFLAGS) $(WASM_VM_EXTRA_FLAGS) $(VM_CFLAGS) $(ENCODER_SRC) $(VM_LIBS) -o $@

$(DECODER_VM): $(DECODER_SRC) decoder.h cte.h
	@echo "Building VM Decoder: $@"
	$(CC) $(WASM_FLAGS) $(CFLAGS) $(WASM_VM_EXTRA_FLAGS) $(VM_CFLAGS) $(DECODER_SRC) $(VM_LIBS) -o $@

$(TEST_TARGET): $(TEST_SRC) cte.c encoder.c decoder.c encoder.h decoder.h cte.h
	@echo "Building Native Test: $@"
	$(CC) $(CFLAGS) $(TEST_CFLAGS) $(TEST_SRC) cte.c encoder.c decoder.c $(TEST_LIBS) -o $@

mvp: $(ENCODER_MVP) $(DECODER_MVP)
vm:  $(ENCODER_VM) $(DECODER_VM)
test_target: $(TEST_TARGET)

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(ENCODER_MVP) $(DECODER_MVP) $(ENCODER_VM) $(DECODER_VM) $(TEST_TARGET) *.o
