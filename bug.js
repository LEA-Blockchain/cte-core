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
    const totalLength = data.length;
    const edgeLength = 10;

    if (totalLength <= 2 * edgeLength) {
        const hexString = Array.from(data)
            .map(b => b.toString(16).padStart(2, '0').toUpperCase())
            .join(' ');
        console.log(`${label} (${totalLength} bytes): ${hexString}`);
    } else {
        const firstPart = Array.from(data.slice(0, edgeLength))
            .map(b => b.toString(16).padStart(2, '0').toUpperCase())
            .join(' ');
        const lastPart = Array.from(data.slice(-edgeLength))
            .map(b => b.toString(16).padStart(2, '0').toUpperCase())
            .join(' ');

        console.log(`${label} (${totalLength} bytes): ${firstPart} ... ${lastPart}`);
    }
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
    let encoderInstance;
    let decoderInstance;

    const createLogger = (instanceProvider, name) => (ptr) => {
        const instance = instanceProvider();
        if (instance) {
            const readString = createStringReader(instance);
            console.error(`WASM LOG [${name}]: ${readString(ptr)}`);
        } else {
            console.error(`WASM LOG [${name}] (instance not ready, pointer: ${ptr})`);
        }
    };

    const encoderImportObject = {
        env: {
            __lea_log: createLogger(() => encoderInstance, 'encoder'),
            __cte_data_handler: (type, dataPtr, size) => {
                // Not used in this minimal test
            },
        }
    };

    const decoderImportObject = {
        env: {
            __lea_log: createLogger(() => decoderInstance, 'decoder'),
            __cte_data_handler: (type, dataPtr, size) => {
                // Not used in this minimal test
            },
        }
    };

    const encoderBuffer = fs.readFileSync(ENCODER_WASM_PATH);
    const { instance: encInst } = await WebAssembly.instantiate(encoderBuffer, encoderImportObject);
    encoderInstance = encInst;
    const encExports = encoderInstance.exports;

    const decoderBuffer = fs.readFileSync(DECODER_WASM_PATH);
    const { instance: decInst } = await WebAssembly.instantiate(decoderBuffer, decoderImportObject);
    decoderInstance = decInst;
    const decExports = decoderInstance.exports;

    console.log('CTE Comprehensive Vector Test\n');

    // Reset the allocators before starting
    if (encExports.__lea_allocator_reset) encExports.__lea_allocator_reset();
    if (decExports.__lea_allocator_reset) decExports.__lea_allocator_reset();
    // --- 2. Encode Data ---
    const enc = encExports.cte_encoder_init(80000);
    console.log('Encoding all vector types and sizes:');

    // Test all Public Key Vector sizes
    const pkKeyCount = 1;
    const pkSizeCodes = [0, 1, 2]; // 32, 64, 128 bytes
    pkSizeCodes.forEach(sizeCode => {
        const keySize = decExports.get_public_key_size(sizeCode);
        const dummyKeys = new Uint8Array(pkKeyCount * keySize).fill(0xAA + sizeCode);
        const keysPtr = encExports.__lea_malloc(dummyKeys.length);
        new Uint8Array(encExports.memory.buffer).set(dummyKeys, keysPtr);
        encExports.cte_encoder_add_public_key_vector(enc, pkKeyCount, sizeCode, keysPtr);
        console.log(`  - Public Key Vector (Size Code: ${sizeCode}, Size: ${keySize}, Count: ${pkKeyCount})`);
    });

    // Test all Signature Vector sizes
    const sigCount = 1;
    const sigSizeCodes = [0, 1, 2, 3]; // 32, 64, 128, 29792 bytes
    sigSizeCodes.forEach(sizeCode => {
        const itemSize = decExports.get_signature_item_size(sizeCode);
        const dummySigs = new Uint8Array(sigCount * itemSize).fill(0xBB + sizeCode);
        const sigsPtr = encExports.__lea_malloc(dummySigs.length);
        console.log('sigsPtr', sigsPtr);
        new Uint8Array(encExports.memory.buffer).set(dummySigs, sigsPtr);
        encExports.cte_encoder_add_signature_vector(enc, sigCount, sizeCode, sigsPtr);
        console.log(`  - Signature Vector (Size Code: ${sizeCode}, Size: ${itemSize}, Count: ${sigCount})`);
    });

    encExports.cte_encoder_write_ixdata_vector_index(enc, 1);
    console.log('  - IxData Vector Index (1)');


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
    console.log('\nDecoding...');

    const PEEK_EOF = 255;
    let type;
    while ((type = decExports.cte_decoder_peek_type(dec)) !== PEEK_EOF) {
        console.log(`\nJS Loop -> Peeked Type: ${type}`);

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
        } else {
            console.log("  - Skipping type (not implemented in this test script)");
            break;
        }
    }

    console.log('\n--- Test Complete ---');
}

main().catch(console.error);
