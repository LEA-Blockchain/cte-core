const fs = require('fs');
const path = require('path');

// --- Configuration ---
const ENCODER_WASM_PATH = path.join(__dirname, 'encoder.mvp.wasm');
const DECODER_WASM_PATH = path.join(__dirname, 'decoder.mvp.wasm');

// --- CTE Peek Type Identifiers ---
// These constants are copied from cte.h for clarity in the JS test.
const CTE_PEEK_TYPE_PK_VECTOR_SIZE_0 = 0;
const CTE_PEEK_TYPE_PK_VECTOR_SIZE_1 = 1;
const CTE_PEEK_TYPE_PK_VECTOR_SIZE_2 = 2;
const CTE_PEEK_TYPE_PK_VECTOR_SIZE_3 = 3; // Unused
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
    const receivedData = [];
    let decoderInstance; // Will be set during instantiation

    const importObject = {
        env: {
            __lea_log: (ptr) => {
                if (decoderInstance) {
                    const readString = createStringReader(decoderInstance);
                    console.error(`WASM ABORT: ${readString(ptr)}`);
                } else {
                    console.error(`WASM ABORT (pointer: ${ptr})`);
                }
            },
            __cte_data_handler: (type, dataPtr, size) => {
                const memory = new Uint8Array(decoderInstance.exports.memory.buffer);
                console.log(`
JS Callback -> Received Type: ${type}, Size: ${size}`);
                const data = memory.slice(dataPtr, dataPtr + size);
                receivedData.push({ type, data });

                const dv = new DataView(data.buffer, data.byteOffset, data.length);
                if (type >= CTE_PEEK_TYPE_PK_VECTOR_SIZE_0 && type <= CTE_PEEK_TYPE_SIG_VECTOR_SIZE_3) { // Vectors
                    printHex("  - Received Vector Data", data);
                } else if (type === CTE_PEEK_TYPE_IXDATA_VECTOR_INDEX) { // Vector Index
                    console.log(`  - Received Vector Index: ${dv.getUint8(0)}`);
                } else if (type === CTE_PEEK_TYPE_IXDATA_ULEB128) { // ULEB128
                    console.log(`  - Received ULEB128: ${dv.getBigUint64(0, true)}`);
                } else if (type === CTE_PEEK_TYPE_IXDATA_SLEB128) { // SLEB128
                    console.log(`  - Received SLEB128: ${dv.getBigInt64(0, true)}`);
                } else if (type === CTE_PEEK_TYPE_IXDATA_INT8) { // Int8
                    console.log(`  - Received Int8: ${dv.getInt8(0)}`);
                } else if (type === CTE_PEEK_TYPE_IXDATA_INT16) { // Int16
                    console.log(`  - Received Int16: ${dv.getInt16(0, true)}`);
                } else if (type === CTE_PEEK_TYPE_IXDATA_INT32) { // Int32
                    console.log(`  - Received Int32: ${dv.getInt32(0, true)}`);
                } else if (type === CTE_PEEK_TYPE_IXDATA_INT64) { // Int64
                    console.log(`  - Received Int64: ${dv.getBigInt64(0, true)}`);
                } else if (type === CTE_PEEK_TYPE_IXDATA_UINT8) { // UInt8
                    console.log(`  - Received UInt8: ${dv.getUint8(0)}`);
                } else if (type === CTE_PEEK_TYPE_IXDATA_UINT16) { // UInt16
                    console.log(`  - Received UInt16: ${dv.getUint16(0, true)}`);
                } else if (type === CTE_PEEK_TYPE_IXDATA_UINT32) { // UInt32
                    console.log(`  - Received UInt32: ${dv.getUint32(0, true)}`);
                } else if (type === CTE_PEEK_TYPE_IXDATA_UINT64) { // UInt64
                    console.log(`  - Received UInt64: ${dv.getBigUint64(0, true)}`);
                } else if (type === CTE_PEEK_TYPE_IXDATA_FLOAT32) { // Float32
                    console.log(`  - Received Float32: ${dv.getFloat32(0, true)}`);
                } else if (type === CTE_PEEK_TYPE_IXDATA_FLOAT64) { // Float64
                    console.log(`  - Received Float64: ${dv.getFloat64(0, true)}`);
                } else if (type === CTE_PEEK_TYPE_IXDATA_CONST_FALSE || type === CTE_PEEK_TYPE_IXDATA_CONST_TRUE) { // Boolean
                    console.log(`  - Received Boolean: ${dv.getUint8(0) !== 0}`);
                } else if (type === CTE_PEEK_TYPE_VECTOR_SHORT || type === CTE_PEEK_TYPE_VECTOR_EXTENDED) { // Vector Data
                    printHex("  - Received Vector Data", data);
                }
            }
        }
    };

    const encoderBuffer = fs.readFileSync(ENCODER_WASM_PATH);
    const { instance: encoderInstance } = await WebAssembly.instantiate(encoderBuffer, importObject);
    const encExports = encoderInstance.exports;

    const decoderBuffer = fs.readFileSync(DECODER_WASM_PATH);
    const { instance } = await WebAssembly.instantiate(decoderBuffer, importObject);
    decoderInstance = instance;
    const decExports = decoderInstance.exports;

    console.log('CTE Encoder/Decoder WASM Test\n');
    
    // Reset the allocators before starting
    if (encExports.__lea_allocator_reset) encExports.__lea_allocator_reset();
    if (decExports.__lea_allocator_reset) decExports.__lea_allocator_reset();

    // --- 2. Encode Data ---
    console.log('Encoding:');
    const enc = encExports.cte_encoder_init(2048);

    const keyCount = 2;
    const keySizeCode = 0; // 32-byte keys
    const dummyKeys = new Uint8Array(2 * 32);
    for (let i = 0; i < dummyKeys.length; ++i) dummyKeys[i] = 0xAA + i;
    const keysPtr = encExports.__lea_malloc(dummyKeys.length);
    new Uint8Array(encExports.memory.buffer).set(dummyKeys, keysPtr);
    encExports.cte_encoder_add_public_key_vector(enc, keyCount, keySizeCode, keysPtr);
    console.log(`  - Public Key Vector (Size Code: ${keySizeCode}, Count: ${keyCount})`);

    encExports.cte_encoder_write_ixdata_vector_index(enc, 1);
    console.log('  - IxData Vector Index (1)');

    const sigCount = 1;
    const sigSizeCode = 1; // 64-byte sigs
    const dummySigs = new Uint8Array(1 * 64);
    for (let i = 0; i < dummySigs.length; ++i) dummySigs[i] = 0xBB + i;
    const sigsPtr = encExports.__lea_malloc(dummySigs.length);
    new Uint8Array(encExports.memory.buffer).set(dummySigs, sigsPtr);
    encExports.cte_encoder_add_signature_vector(enc, sigCount, sigSizeCode, sigsPtr);
    console.log(`  - Signature Vector (Size Code: ${sigSizeCode}, Count: ${sigCount})`);

    encExports.cte_encoder_write_ixdata_vector_index(enc, 0);
    console.log('  - IxData Vector Index (0)');
    
    encExports.cte_encoder_write_ixdata_sleb128(enc, -78910n);
    console.log('  - IxData SLEB128 (-78910)');

    encExports.cte_encoder_write_ixdata_boolean(enc, true);
    console.log('  - IxData Boolean (true)');
    encExports.cte_encoder_write_ixdata_boolean(enc, false);
    console.log('  - IxData Boolean (false)');

    encExports.cte_encoder_write_ixdata_int8(enc, -128);
    console.log('  - IxData Int8 (-128)');
    encExports.cte_encoder_write_ixdata_uint8(enc, 255);
    console.log('  - IxData UInt8 (255)');

    encExports.cte_encoder_write_ixdata_int16(enc, -32768);
    console.log('  - IxData Int16 (-32768)');
    encExports.cte_encoder_write_ixdata_uint16(enc, 65535);
    console.log('  - IxData UInt16 (65535)');

    encExports.cte_encoder_write_ixdata_int32(enc, -2147483648);
    console.log('  - IxData Int32 (-2147483648)');
    encExports.cte_encoder_write_ixdata_uint32(enc, 4294967295);
    console.log('  - IxData UInt32 (4294967295)');

    encExports.cte_encoder_write_ixdata_int64(enc, -9223372036854775808n);
    console.log('  - IxData Int64 (-9223372036854775808)');
    encExports.cte_encoder_write_ixdata_uint64(enc, 18446744073709551615n);
    console.log('  - IxData UInt64 (18446744073709551615)');

    encExports.cte_encoder_write_ixdata_float32(enc, 123.456);
    console.log('  - IxData Float32 (123.456)');
    encExports.cte_encoder_write_ixdata_float64(enc, 789.0123456789);
    console.log('  - IxData Float64 (789.0123456789)');

    const shortCmd = new TextEncoder().encode("Short payload");
    const shortCmdPtr = encExports.__lea_malloc(shortCmd.length);
    new Uint8Array(encExports.memory.buffer).set(shortCmd, shortCmdPtr);
    encExports.cte_encoder_add_vector_data(enc, shortCmd.length, shortCmdPtr);
    console.log(`  - Vector Data (Short, Len: ${shortCmd.length})`);
    
    const longCmd = new Uint8Array(40);
    for (let i = 0; i < longCmd.length; i++) longCmd[i] = i;
    const longCmdPtr = encExports.__lea_malloc(longCmd.length);
    new Uint8Array(encExports.memory.buffer).set(longCmd, longCmdPtr);
    encExports.cte_encoder_add_vector_data(enc, longCmd.length, longCmdPtr);
    console.log(`  - Vector Data (Extended, Len: ${longCmd.length})`);


    // --- 3. Retrieve Encoded Data & Setup Decoder ---
    const encodedDataPtr = encExports.cte_encoder_get_data(enc);
    const encodedDataSize = encExports.cte_encoder_get_size(enc);
    const encodedData = new Uint8Array(encExports.memory.buffer).slice(encodedDataPtr, encodedDataPtr + encodedDataSize);

    console.log(`\nTotal Encoded Size: ${encodedDataSize} bytes`);
    printHex("Encoded Data", encodedData);

    const dec = decExports.cte_decoder_init(encodedDataSize);
    const decoderLoadPtr = decExports.cte_decoder_load(dec);
    new Uint8Array(decExports.memory.buffer).set(encodedData, decoderLoadPtr);

    // --- 4. Decode Data with Host Callback ---
    console.log('\nDecoding with Host Callback:');
    const result = decExports.cte_decoder_run(dec);
    console.log(`\nCallback decoding finished with result: ${result}`);

    // Basic assertion to verify the test ran
    if (receivedData.length !== 19) {
         console.error(`\n[FAIL] Expected 19 data callbacks, but received ${receivedData.length}`);
    } else {
         console.log(`\n[PASS] Received 19 data callbacks as expected.`);
    }

    console.log('\n--- Test Complete ---');
}

main().catch(console.error);
