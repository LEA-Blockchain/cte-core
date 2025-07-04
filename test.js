const fs = require('fs');
const path = require('path');

// --- Configuration ---
const ENCODER_WASM_PATH = path.join(__dirname, 'encoder.mvp.wasm');
const DECODER_WASM_PATH = path.join(__dirname, 'decoder.mvp.wasm');

// --- CTE Peek Type Identifiers ---
const CTE_PEEK_TYPE_PK_VECTOR_SIZE_0 = 0;
const CTE_PEEK_TYPE_PK_VECTOR_SIZE_1 = 1;
const CTE_PEEK_TYPE_PK_VECTOR_SIZE_2 = 2;
const CTE_PEEK_TYPE_SIG_VECTOR_SIZE_0 = 4;
const CTE_PEEK_TYPE_SIG_VECTOR_SIZE_1 = 5;
const CTE_PEEK_TYPE_SIG_VECTOR_SIZE_2 = 6;
const CTE_PEEK_TYPE_SIG_VECTOR_SIZE_3 = 7;
const CTE_PEEK_TYPE_IXDATA_VECTOR_INDEX = 8;
const CTE_PEEK_TYPE_IXDATA_ULEB128 = 9;
const CTE_PEEK_TYPE_IXDATA_SLEB128 = 10;
const CTE_PEEK_TYPE_IXDATA_INT8 = 11;
const CTE_PEEK_TYPE_IXDATA_INT16 = 12;
const CTE_PEEK_TYPE_IXDATA_INT32 = 13;
const CTE_PEEK_TYPE_IXDATA_INT64 = 14;
const CTE_PEEK_TYPE_IXDATA_UINT8 = 15;
const CTE_PEEK_TYPE_IXDATA_UINT16 = 16;
const CTE_PEEK_TYPE_IXDATA_UINT32 = 17;
const CTE_PEEK_TYPE_IXDATA_UINT64 = 18;
const CTE_PEEK_TYPE_IXDATA_FLOAT32 = 19;
const CTE_PEEK_TYPE_IXDATA_FLOAT64 = 20;
const CTE_PEEK_TYPE_IXDATA_CONST_FALSE = 21;
const CTE_PEEK_TYPE_IXDATA_CONST_TRUE = 22;
const CTE_PEEK_TYPE_VECTOR_SHORT = 23;
const CTE_PEEK_TYPE_VECTOR_EXTENDED = 24;

// --- Test Configuration ---
const PK_SIZES = [32, 64, 128];
// Test the large signature separately due to memory constraints
const SIG_SIZES_BATCH_1 = [32, 64, 128];
const SIG_SIZES_BATCH_2 = [29792];


/**
 * A helper function to print a Uint8Array in hexadecimal format.
 */
function printHex(label, data) {
    const hexString = Array.from(data).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
    console.log(`${label} (${data.length} bytes): ${hexString}`);
}

/**
 * Creates a helper function to read a null-terminated string from a specific
 * WASM instance's memory.
 */
function createStringReader(wasmInstance) {
    const memory = new Uint8Array(wasmInstance.exports.memory.buffer);
    return (ptr) => {
        let end = ptr;
        while (memory[end] !== 0) {
            end++;
        }
        return new TextDecoder().decode(memory.subarray(ptr, end));
    };
}

/**
 * Main test function.
 */
async function main() {
    if (!fs.existsSync(ENCODER_WASM_PATH) || !fs.existsSync(DECODER_WASM_PATH)) {
        console.error(`WASM file(s) not found. Please compile the C code.`);
        process.exit(1);
    }

    let receivedData = [];
    let encoderInstance, decoderInstance;

    const importObject = {
        env: {
            __lea_log: (ptr) => {
                let message = `WASM ABORT (pointer: ${ptr})`;
                // Try to read from the decoder instance, but don't crash if it's not available
                // or if the memory is corrupt. This makes logging robust.
                try {
                    if (decoderInstance) {
                        const readString = createStringReader(decoderInstance);
                        message = `WASM ABORT: ${readString(ptr)}`;
                    } else if (encoderInstance) {
                        const readString = createStringReader(encoderInstance);
                        message = `WASM ABORT: ${readString(ptr)}`;
                    }
                } catch (e) {}
                console.error(message);
            },
            __cte_data_handler: (type, dataPtr, size) => {
                const memory = new Uint8Array(decoderInstance.exports.memory.buffer);
                const data = memory.slice(dataPtr, dataPtr + size);
                receivedData.push({ type, data });
            }
        }
    };

    // --- Instantiate Modules ---
    const encoderBuffer = fs.readFileSync(ENCODER_WASM_PATH);
    ({ instance: encoderInstance } = await WebAssembly.instantiate(encoderBuffer, importObject));
    const encExports = encoderInstance.exports;

    const decoderBuffer = fs.readFileSync(DECODER_WASM_PATH);
    ({ instance: decoderInstance } = await WebAssembly.instantiate(decoderBuffer, importObject));
    const decExports = decoderInstance.exports;

    console.log('CTE Encoder/Decoder WASM Test\n');

    // =================================================================
    // --- BATCH 1: Standard Data Types and Smaller Vectors ---
    // =================================================================
    console.log('--- Batch 1: Standard Data Types ---');
    let enc = encExports.cte_encoder_init(4096);

    const addVector = (addFn, count, sizeCode, itemSize, fillByte, name) => {
        const dummyData = new Uint8Array(count * itemSize);
        const ptr = encExports.__lea_malloc(dummyData.length);
        new Uint8Array(encExports.memory.buffer).set(dummyData, ptr);
        addFn(enc, count, sizeCode, ptr);
        console.log(`  - ${name} (Size Code: ${sizeCode}, Count: ${count})`);
    };
    
    for (let i = 0; i < PK_SIZES.length; i++) {
        addVector(encExports.cte_encoder_add_public_key_vector, 2, i, PK_SIZES[i], 0xAA, "Public Key Vector");
    }
    for (let i = 0; i < SIG_SIZES_BATCH_1.length; i++) {
        addVector(encExports.cte_encoder_add_signature_vector, 1, i, SIG_SIZES_BATCH_1[i], 0xBB, "Signature Vector");
    }
    encExports.cte_encoder_write_ixdata_uint32(enc, 12345);
    
    let encodedDataPtr = encExports.cte_encoder_get_data(enc);
    let encodedDataSize = encExports.cte_encoder_get_size(enc);
    let encodedData = new Uint8Array(encExports.memory.buffer).slice(encodedDataPtr, encodedDataPtr + encodedDataSize);
    
    let dec = decExports.cte_decoder_init(encodedDataSize);
    let decoderLoadPtr = decExports.cte_decoder_load(dec);
    new Uint8Array(decExports.memory.buffer).set(encodedData, decoderLoadPtr);
    
    receivedData = [];
    decExports.cte_decoder_run(dec);

    const expected_batch1 = PK_SIZES.length + SIG_SIZES_BATCH_1.length + 1;
    if (receivedData.length !== expected_batch1) {
        console.error(`\n[FAIL] Batch 1: Expected ${expected_batch1} callbacks, got ${receivedData.length}`);
    } else {
        console.log(`\n[PASS] Batch 1: Received ${receivedData.length} callbacks as expected.`);
    }

    // =================================================================
    // --- BATCH 2: Large Signature Vector ---
    // =================================================================
    console.log('\n--- Batch 2: Large Signature Vector ---');
    encExports.cte_encoder_reset(); // Hard reset of the allocator
    enc = encExports.cte_encoder_init(32768); // Re-init with a large buffer

    addVector(encExports.cte_encoder_add_signature_vector, 1, 3, SIG_SIZES_BATCH_2[0], 0xCC, "Large Signature Vector");

    encodedDataPtr = encExports.cte_encoder_get_data(enc);
    encodedDataSize = encExports.cte_encoder_get_size(enc);
    encodedData = new Uint8Array(encExports.memory.buffer).slice(encodedDataPtr, encodedDataPtr + encodedDataSize);

    decExports.cte_decoder_reset(); // Hard reset
    dec = decExports.cte_decoder_init(encodedDataSize);
    decoderLoadPtr = decExports.cte_decoder_load(dec);
    new Uint8Array(decExports.memory.buffer).set(encodedData, decoderLoadPtr);

    receivedData = [];
    decExports.cte_decoder_run(dec);

    if (receivedData.length !== 1) {
        console.error(`\n[FAIL] Batch 2: Expected 1 callback, got ${receivedData.length}`);
    } else {
        console.log(`\n[PASS] Batch 2: Received 1 callback as expected.`);
    }

    // =================================================================
    // --- BATCH 3: Full Reset Functionality Test ---
    // =================================================================
    console.log('\n--- Batch 3: Reset Functionality ---');
    
    console.log('Resetting encoder and re-encoding...');
    encExports.cte_encoder_reset();
    enc = encExports.cte_encoder_init(128); 
    encExports.cte_encoder_write_ixdata_boolean(enc, true);
    
    const encodedDataSize2 = encExports.cte_encoder_get_size(enc);
    const encodedDataPtr2 = encExports.cte_encoder_get_data(enc);
    const encodedData2 = new Uint8Array(encExports.memory.buffer).slice(encodedDataPtr2, encodedDataPtr2 + encodedDataSize2);
    
    console.log('Resetting decoder and re-decoding...');
    decExports.cte_decoder_reset();
    dec = decExports.cte_decoder_init(encodedDataSize2);
    const decoderLoadPtr2 = decExports.cte_decoder_load(dec);
    new Uint8Array(decExports.memory.buffer).set(encodedData2, decoderLoadPtr2);
    
    receivedData = [];
    const result2 = decExports.cte_decoder_run(dec);
    
    if (result2 !== 0) {
        console.error(`\n[FAIL] Batch 3: Decoder run failed after reset.`);
    } else if (receivedData.length !== 1) {
        console.error(`\n[FAIL] Batch 3: Expected 1 item after reset, but got ${receivedData.length}.`);
    } else if (receivedData[0].type !== CTE_PEEK_TYPE_IXDATA_CONST_TRUE) {
        console.error(`\n[FAIL] Batch 3: After reset, expected type ${CTE_PEEK_TYPE_IXDATA_CONST_TRUE} but got ${receivedData[0].type}`);
    } else {
        console.log(`\n[PASS] Batch 3: Reset functionality test successful.`);
    }

    console.log('\n--- Test Complete ---');
}

main().catch(console.error);