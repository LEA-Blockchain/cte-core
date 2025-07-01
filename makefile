TARGET_MVP_ENC := encoder.mvp.wasm
TARGET_MVP_DEC := decoder.mvp.wasm
TARGET_VM_ENC := encoder.vm.wasm
TARGET_VM_DEC := decoder.vm.wasm
TARGET_NATIVE_TEST := test
TARGET_CTETOOL := ctetool

# Compiler and flags
CC := clang
CFLAGS_WASM_BASE := --target=wasm32 -nostdlib -ffreestanding -nobuiltininc -Wl,--no-entry -Os -Wall -Wextra -pedantic
CFLAGS_WASM_MVP := $(CFLAGS_WASM_BASE)
CFLAGS_WASM_LEA := $(CFLAGS_WASM_BASE) -mnontrapping-fptoint -mbulk-memory -msign-ext -msimd128 -mtail-call -mreference-types -matomics -mmultivalue -Xclang -target-abi -Xclang experimental-mv
CFLAGS_NATIVE := -Os -Wall -Wextra -pedantic

# Lea-specific paths and libraries
LEA_INCLUDE_PATH := /usr/local/include/stdlea
LEA_LIB_PATH := /usr/local/lib
LEA_MVP_LIB := -lstdlea-mvp
LEA_VM_LIB := -lstdlea-lea
LEA_NATIVE_LIB := -lstdlea

# Source files
SRC_CTE := cte.c
SRC_ENC := encoder.c
SRC_DEC := decoder.c
SRC_TEST := test.c
SRC_CTETOOL := ctetool.c

.PHONY: all clean

all: wasm_mvp wasm_vm native_test $(TARGET_CTETOOL)

# MVP WASM Targets (MVP ABI)
wasm_mvp: $(TARGET_MVP_ENC) $(TARGET_MVP_DEC)

$(TARGET_MVP_ENC): $(SRC_CTE) $(SRC_ENC)
	@echo "Building MVP Encoder: $@"
	$(CC) $(CFLAGS_WASM_MVP) -I$(LEA_INCLUDE_PATH) -DENV_WASM_MVP $(SRC_CTE) $(SRC_ENC) -L$(LEA_LIB_PATH) $(LEA_MVP_LIB) -flto -o $@

$(TARGET_MVP_DEC): $(SRC_CTE) $(SRC_DEC)
	@echo "Building MVP Decoder: $@"
	$(CC) $(CFLAGS_WASM_MVP) -I$(LEA_INCLUDE_PATH) -DENV_WASM_MVP $(SRC_CTE) $(SRC_DEC) -L$(LEA_LIB_PATH) $(LEA_MVP_LIB) -flto -o $@

# Lea VM WASM Targets (VM ABI)
wasm_vm: $(TARGET_VM_ENC) $(TARGET_VM_DEC)

$(TARGET_VM_ENC): $(SRC_CTE) $(SRC_ENC)
	@echo "Building VM Encoder: $@"
	$(CC) $(CFLAGS_WASM_LEA) -I$(LEA_INCLUDE_PATH) -DENV_WASM_LEA $(SRC_CTE) $(SRC_ENC) -L$(LEA_LIB_PATH) $(LEA_VM_LIB) -flto -o $@

$(TARGET_VM_DEC): $(SRC_CTE) $(SRC_DEC)
	@echo "Building VM Decoder: $@"
	$(CC) $(CFLAGS_WASM_LEA) -I$(LEA_INCLUDE_PATH) -DENV_WASM_LEA $(SRC_CTE) $(SRC_DEC) -L$(LEA_LIB_PATH) $(LEA_VM_LIB) -flto -o $@

# Native Test Target
native_test: $(TARGET_NATIVE_TEST)

$(TARGET_NATIVE_TEST): $(SRC_TEST) $(SRC_CTE) $(SRC_ENC) $(SRC_DEC)
	@echo "Building Native Test: $@"
	$(CC) $(CFLAGS_NATIVE) -I$(LEA_INCLUDE_PATH) $(SRC_TEST) $(SRC_CTE) $(SRC_ENC) $(SRC_DEC) -L$(LEA_LIB_PATH) $(LEA_NATIVE_LIB) -o $@



$(TARGET_CTETOOL): $(SRC_CTETOOL) $(SRC_CTE) $(SRC_ENC) $(SRC_DEC)
	@echo "Building CTE Tool: $@"
	$(CC) $(CFLAGS_NATIVE) -I$(LEA_INCLUDE_PATH) $(SRC_CTETOOL) $(SRC_CTE) $(SRC_ENC) $(SRC_DEC) -L$(LEA_LIB_PATH) $(LEA_NATIVE_LIB) -o $@

# Clean rule
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(TARGET_MVP_ENC) $(TARGET_MVP_DEC) $(TARGET_VM_ENC) $(TARGET_VM_DEC) $(TARGET_NATIVE_TEST) $(TARGET_CTETOOL) *.o

