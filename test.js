const fs = require('fs');
const path = require('path');

// --- Configuration ---
const ENCODER_WASM_PATH = path.join(__dirname, 'encoder.mvp.wasm');
const DECODER_WASM_PATH = path.join(__dirname, 'decoder.mvp.wasm');

/**
 * A helper function to print a Uint8Array in hexadecimal format.
 * @param {string} label A label to print before the hex data.
 * @param {Uint8Array} data The data to print.
 */
function printHex(label, data) {
    const hexString = Array.from(data).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
    console.log(`${label} (${data.length} bytes): ${hexString}`);
}

/**
 * Creates a helper function to read a null-terminated string from a specific
 * WASM instance's memory.
 * @param {WebAssembly.Instance} wasmInstance The WASM instance.
 * @returns {function(number): string} A function that takes a pointer and returns a string.
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
        console.error(`WASM file(s) not found.`);
        console.error(`- Encoder: ${ENCODER_WASM_PATH}`);
        console.error(`- Decoder: ${DECODER_WASM_PATH}`);
        console.error('Please make sure you have compiled the C code to wasm.');
        process.exit(1);
    }

    // --- 1. Setup Environment and Instantiate WASM Modules ---
    const importObject = {
        env: {
            __log_lea: (ptr) => console.error(`WASM ABORT (pointer: ${ptr})`)
        }
    };

    const encoderBuffer = fs.readFileSync(ENCODER_WASM_PATH);
    const { instance: encoderInstance } = await WebAssembly.instantiate(encoderBuffer, importObject);
    const encExports = encoderInstance.exports;
    const readEncoderString = createStringReader(encoderInstance);
    importObject.env.__log_lea = (ptr) => console.error(`ENCODER ABORT: ${readEncoderString(ptr)}`);

    const decoderBuffer = fs.readFileSync(DECODER_WASM_PATH);
    const { instance: decoderInstance } = await WebAssembly.instantiate(decoderBuffer, importObject);
    const decExports = decoderInstance.exports;
    const readDecoderString = createStringReader(decoderInstance);
    importObject.env.__log_lea = (ptr) => console.error(`DECODER ABORT: ${readDecoderString(ptr)}`);

    console.log('CTE Encoder/Decoder WASM Test\n');
    
    // Reset the allocators before starting
    encExports.allocator_reset();
    decExports.allocator_reset();

    // --- 2. Encode Data ---
    console.log('Encoding:');
    const enc = encExports.cte_encoder_init(2048);

    const keyCount = 2;
    const keySizeCode = 0; // 32-byte keys
    const dummyKeys = new Uint8Array(2 * 32);
    for (let i = 0; i < dummyKeys.length; ++i) dummyKeys[i] = 0xAA + i;
    const keysPtr = encExports.malloc(dummyKeys.length);
    new Uint8Array(encExports.memory.buffer).set(dummyKeys, keysPtr);
    encExports.cte_encoder_add_public_key_vector(enc, keyCount, keySizeCode, keysPtr);
    console.log(`  - Public Key Vector (Size Code: ${keySizeCode}, Count: ${keyCount})`);

    encExports.cte_encoder_write_ixdata_vector_index(enc, 1);
    console.log('  - IxData Vector Index (1)');

    const sigCount = 1;
    const sigSizeCode = 1; // 64-byte sigs
    const dummySigs = new Uint8Array(1 * 64);
    for (let i = 0; i < dummySigs.length; ++i) dummySigs[i] = 0xBB + i;
    const sigsPtr = encExports.malloc(dummySigs.length);
    new Uint8Array(encExports.memory.buffer).set(dummySigs, sigsPtr);
    encExports.cte_encoder_add_signature_vector(enc, sigCount, sigSizeCode, sigsPtr);
    console.log(`  - Signature Vector (Size Code: ${sigSizeCode}, Count: ${sigCount})`);

    encExports.cte_encoder_write_ixdata_vector_index(enc, 0);
    console.log('  - IxData Vector Index (0)');
    
    encExports.cte_encoder_write_ixdata_uleb128(enc, 123456n);
    console.log('  - IxData ULEB128 (123456)');
    
    encExports.cte_encoder_write_ixdata_sleb128(enc, -78910n);
    console.log('  - IxData SLEB128 (-78910)');

    encExports.cte_encoder_write_ixdata_boolean(enc, true);
    console.log('  - IxData Boolean (true)');
    encExports.cte_encoder_write_ixdata_boolean(enc, false);
    console.log('  - IxData Boolean (false)');

    const shortCmd = new TextEncoder().encode("Short payload");
    const shortCmdPtr = encExports.malloc(shortCmd.length);
    new Uint8Array(encExports.memory.buffer).set(shortCmd, shortCmdPtr);
    encExports.cte_encoder_add_vector_data(enc, shortCmd.length, shortCmdPtr);
    console.log(`  - Vector Data (Short, Len: ${shortCmd.length})`);

    // --- 3. Retrieve Encoded Data & Setup Decoder ---
    const encodedDataPtr = encExports.cte_encoder_get_data(enc);
    const encodedDataSize = encExports.cte_encoder_get_size(enc);
    const encodedData = new Uint8Array(encExports.memory.buffer).slice(encodedDataPtr, encodedDataPtr + encodedDataSize);

    console.log(`\nTotal Encoded Size: ${encodedDataSize} bytes`);
    printHex("Encoded Data", encodedData);

    const dec = decExports.cte_decoder_init(encodedDataSize);
    const decoderLoadPtr = decExports.cte_decoder_load(dec);
    new Uint8Array(decExports.memory.buffer).set(encodedData, decoderLoadPtr);

    // --- 4. Decode Data with Manual Loop ---
    console.log('\nDecoding Iteratively with Manual Peek/Read Loop:');
    
    const PEEK_EOF = 255;
    let type;
    while ((type = decExports.cte_decoder_peek_type(dec)) !== PEEK_EOF) {
        console.log(`\nJS Loop -> Peeked Type: ${type}`);
        
        // This is a simplified version of the C test's switch statement
        if (type >= 0 && type <= 3) { // PK Vector
            const dataPtr = decExports.cte_decoder_read_public_key_vector_data(dec);
            const count = decExports.cte_decoder_get_last_vector_count(dec);
            const itemSize = decExports.get_public_key_size(type - 0);
            const data = new Uint8Array(decExports.memory.buffer, dataPtr, count * itemSize);
            printHex("  - Read PK Vector Data", data);
        } else if (type >= 4 && type <= 7) { // Sig Vector
            const dataPtr = decExports.cte_decoder_read_signature_vector_data(dec);
            const count = decExports.cte_decoder_get_last_vector_count(dec);
            const itemSize = decExports.get_signature_item_size(type - 4);
            const data = new Uint8Array(decExports.memory.buffer, dataPtr, count * itemSize);
            printHex("  - Read Sig Vector Data", data);
        } else if (type === 8) { // Vector Index
            const index = decExports.cte_decoder_read_ixdata_vector_index(dec);
            console.log(`  - Read Vector Index: ${index}`);
        } else if (type === 10) { // ULEB128
            const val = decExports.cte_decoder_read_ixdata_uleb128(dec);
            console.log(`  - Read ULEB128: ${val}`);
        } else if (type === 11) { // SLEB128
            const val = decExports.cte_decoder_read_ixdata_sleb128(dec);
            console.log(`  - Read SLEB128: ${val}`);
        } else if (type === 22 || type === 23) { // Boolean
            const val = decExports.cte_decoder_read_ixdata_boolean(dec);
            console.log(`  - Read Boolean: ${val}`);
        } else if (type === 24 || type === 25) { // Vector Data
            const dataPtr = decExports.cte_decoder_read_vector_data_payload(dec);
            const len = decExports.cte_decoder_get_last_vector_data_payload_length(dec);
            const data = new Uint8Array(decExports.memory.buffer, dataPtr, len);
            printHex("  - Read Vector Data", data);
        } else {
            console.log("  - Skipping type (not implemented in this test script)");
            // A real implementation would need to skip unknown fields
            // For now, we'll just abort to keep the test simple.
            break; 
        }
    }

    console.log('\n--- Test Complete ---');
}

main().catch(console.error);