#include "decoder.h"
#include "encoder.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define BUFFER_SIZE 2048

/**
 * @brief Gets a human-readable name for a given peek type identifier.
 * @param type The peek type identifier (e.g., CTE_PEEK_TYPE_PK_VECTOR_SIZE_0).
 * @return A const character string representing the name.
 */
const char *get_type_name(int type)
{
    switch (type)
    {
    // PK Vectors
    case CTE_PEEK_TYPE_PK_VECTOR_SIZE_0:
        return "PK Vector (32-byte)";
    case CTE_PEEK_TYPE_PK_VECTOR_SIZE_1:
        return "PK Vector (64-byte)";
    case CTE_PEEK_TYPE_PK_VECTOR_SIZE_2:
        return "PK Vector (128-byte)";
    // Sig Vectors
    case CTE_PEEK_TYPE_SIG_VECTOR_SIZE_0:
        return "Sig Vector (32-byte)";
    case CTE_PEEK_TYPE_SIG_VECTOR_SIZE_1:
        return "Sig Vector (64-byte)";
    case CTE_PEEK_TYPE_SIG_VECTOR_SIZE_2:
        return "Sig Vector (128-byte)";
    case CTE_PEEK_TYPE_SIG_VECTOR_SIZE_3:
        return "Sig Vector (29792-byte)";
    // IxData
    case CTE_PEEK_TYPE_IXDATA_VECTOR_INDEX:
        return "IxData Vector Index";
    case CTE_PEEK_TYPE_IXDATA_VARINT_ZERO:
        return "IxData Varint Zero";
    case CTE_PEEK_TYPE_IXDATA_ULEB128:
        return "IxData ULEB128";
    case CTE_PEEK_TYPE_IXDATA_SLEB128:
        return "IxData SLEB128";
    case CTE_PEEK_TYPE_IXDATA_INT8:
        return "IxData Int8";
    case CTE_PEEK_TYPE_IXDATA_INT16:
        return "IxData Int16";
    case CTE_PEEK_TYPE_IXDATA_INT32:
        return "IxData Int32";
    case CTE_PEEK_TYPE_IXDATA_INT64:
        return "IxData Int64";
    case CTE_PEEK_TYPE_IXDATA_UINT8:
        return "IxData Uint8";
    case CTE_PEEK_TYPE_IXDATA_UINT16:
        return "IxData Uint16";
    case CTE_PEEK_TYPE_IXDATA_UINT32:
        return "IxData Uint32";
    case CTE_PEEK_TYPE_IXDATA_UINT64:
        return "IxData Uint64";
    case CTE_PEEK_TYPE_IXDATA_FLOAT32:
        return "IxData Float32";
    case CTE_PEEK_TYPE_IXDATA_FLOAT64:
        return "IxData Float64";
    case CTE_PEEK_TYPE_IXDATA_CONST_FALSE:
        return "IxData Boolean False";
    case CTE_PEEK_TYPE_IXDATA_CONST_TRUE:
        return "IxData Boolean True";
    // Vector Data
    case CTE_PEEK_TYPE_VECTOR_SHORT:
        return "Vector Data Short";
    case CTE_PEEK_TYPE_VECTOR_EXTENDED:
        return "Vector Data Extended";
    default:
        return "Unknown Type";
    }
}

/**
 * @brief Prints a block of data in hexadecimal format.
 * @param label A label to print before the hex data.
 * @param data A pointer to the data to print.
 * @param size The number of bytes to print.
 */
void print_hex(const char *label, const uint8_t *data, size_t size)
{
    if (data == NULL && size > 0)
    {
        printf("%s (%zu bytes): <NULL DATA>\n", label, size);
        return;
    }
    if (size == 0)
    {
        printf("%s (0 bytes): <EMPTY>\n", label);
        return;
    }
    printf("%s (%zu bytes): ", label, size);
    for (size_t i = 0; i < size; ++i)
    {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

/**
 * @brief Main entry point for the native CTE test harness.
 *
 * This test performs the following steps:
 * 1. Initializes an encoder.
 * 2. Encodes a comprehensive set of CTE fields in a specific order.
 * 3. Prints the resulting byte stream.
 * 4. Initializes a decoder with the encoded data.
 * 5. Iteratively decodes the stream, peeking at each field's tag and subtype
 *    to determine how to parse it.
 * 6. Verifies that the decoded data matches the original encoded data.
 * 7. Checks for errors, such as final position mismatch.
 *
 * @return 0 on successful completion.
 */
int main()
{
    printf("CTE Encoder/Decoder Native Test\n");

    cte_encoder_t *enc = cte_encoder_init(BUFFER_SIZE);

    // --- Encode Data ---
    printf("Encoding:\n");

    uint8_t key_count_enc = 2;
    uint8_t key_size_code_enc = CTE_VECTOR_ENTRY_SIZE_CODE_0; // 32-byte keys
    uint8_t dummy_keys[2 * CTE_PUBKEY_SIZE_CODE_0];
    for (size_t i = 0; i < sizeof(dummy_keys); ++i)
        dummy_keys[i] = (uint8_t)(0xAA + i);
    void *key_ptr = cte_encoder_begin_public_key_vector(enc, key_count_enc, key_size_code_enc);
    memcpy(key_ptr, dummy_keys, sizeof(dummy_keys));
    printf("  - Public Key Vector (Size Code: %u, Count: %u)\n", key_size_code_enc, key_count_enc);

    cte_encoder_write_ixdata_vector_index(enc, 1);
    printf("  - IxData Vector Index (1)\n");

    uint8_t sig_count_enc = 1;
    uint8_t sig_size_code_enc = CTE_VECTOR_ENTRY_SIZE_CODE_1; // 64-byte sigs
    uint8_t dummy_sig[1 * CTE_SIGNATURE_SIZE_CODE_1];
    for (size_t i = 0; i < sizeof(dummy_sig); ++i)
        dummy_sig[i] = (uint8_t)(0xBB + i);
    void *sig_ptr = cte_encoder_begin_signature_vector(enc, sig_count_enc, sig_size_code_enc);
    memcpy(sig_ptr, dummy_sig, sizeof(dummy_sig));
    printf("  - Signature Vector (Size Code: %u, Count: %u)\n", sig_size_code_enc, sig_count_enc);

    cte_encoder_write_ixdata_vector_index(enc, 0);
    printf("  - IxData Vector Index (0)\n");

    uint64_t uleb_val_enc = 123456;
    cte_encoder_write_ixdata_uleb128(enc, uleb_val_enc);
    printf("  - IxData ULEB128 (%llu)\n", (unsigned long long)uleb_val_enc);

    int64_t sleb_val_enc = -78910;
    cte_encoder_write_ixdata_sleb128(enc, sleb_val_enc);
    printf("  - IxData SLEB128 (%lld)\n", (long long)sleb_val_enc);

    int8_t i8_val_enc = -120;
    cte_encoder_write_ixdata_int8(enc, i8_val_enc);
    printf("  - IxData Int8 (%d)\n", i8_val_enc);

    int16_t i16_val_enc = -30000;
    cte_encoder_write_ixdata_int16(enc, i16_val_enc);
    printf("  - IxData Int16 (%d)\n", i16_val_enc);

    int32_t i32_val_enc = -1000;
    cte_encoder_write_ixdata_int32(enc, i32_val_enc);
    printf("  - IxData Int32 (%d)\n", i32_val_enc);

    uint8_t u8_val_enc = 250;
    cte_encoder_write_ixdata_uint8(enc, u8_val_enc);
    printf("  - IxData Uint8 (%u)\n", u8_val_enc);

    uint16_t u16_val_enc = 60000;
    cte_encoder_write_ixdata_uint16(enc, u16_val_enc);
    printf("  - IxData Uint16 (%u)\n", u16_val_enc);

    uint32_t u32_val_enc = 4000000000;
    cte_encoder_write_ixdata_uint32(enc, u32_val_enc);
    printf("  - IxData Uint32 (%u)\n", u32_val_enc);

    uint64_t u64_val_enc = 9876543210ULL;
    cte_encoder_write_ixdata_uint64(enc, u64_val_enc);
    printf("  - IxData Uint64 (%llu)\n", (unsigned long long)u64_val_enc);

    float f32_val_enc = 3.14159f;
    cte_encoder_write_ixdata_float32(enc, f32_val_enc);
    printf("  - IxData Float32 (%f)\n", f32_val_enc);

    double f64_val_enc = 1.23456789012345;
    cte_encoder_write_ixdata_float64(enc, f64_val_enc);
    printf("  - IxData Float64 (%f)\n", f64_val_enc);

    cte_encoder_write_ixdata_boolean(enc, true);
    printf("  - IxData Boolean (true)\n");
    cte_encoder_write_ixdata_boolean(enc, false);
    printf("  - IxData Boolean (false)\n");

    const char *short_cmd_enc = "Short payload";
    size_t short_len_enc = strlen(short_cmd_enc);
    void *cmd_ptr_short = cte_encoder_begin_vector_data(enc, short_len_enc);
    memcpy(cmd_ptr_short, short_cmd_enc, short_len_enc);
    printf("  - Vector Data (Short, Len: %zu)\n", short_len_enc);

    char long_cmd_enc[200];
    memset(long_cmd_enc, 'L', sizeof(long_cmd_enc));
    long_cmd_enc[199] = '\0';
    size_t long_len_enc = 150;
    void *cmd_ptr_long = cte_encoder_begin_vector_data(enc, long_len_enc);
    memcpy(cmd_ptr_long, long_cmd_enc, long_len_enc);
    printf("  - Vector Data (Extended, Len: %zu)\n", long_len_enc);

    const uint8_t *encoded_data = cte_encoder_get_data(enc);
    size_t encoded_size = cte_encoder_get_size(enc);
    printf("\nTotal Encoded Size: %zu bytes\n", encoded_size);
    print_hex("Encoded Data", encoded_data, encoded_size);

    // --- Decode Data Iteratively ---
    printf("\nDecoding Iteratively with Subtype Peeking:\n");
    cte_decoder_t *dec = cte_decoder_init(encoded_size);
    uint8_t *loadPtr = cte_decoder_load(dec);
    memcpy(loadPtr, encoded_data, encoded_size);

    int ix_legacy_count = 0;
    int ix_const_count = 0;

    while (dec->position < encoded_size)
    {
        size_t current_pos = dec->position;
        int type = cte_decoder_peek_type(dec);

        printf("\nPos: %-3zu -> Peeked Type: %d (%s)\n",
               current_pos, type, get_type_name(type));

        switch (type)
        {
        case CTE_PEEK_TYPE_PK_VECTOR_SIZE_0:
        {
            const uint8_t *data = cte_decoder_read_public_key_vector_data(dec);
            printf("  - Read PubKey Vector. New Pos: %zu\n", dec->position);
            if (memcmp(data, dummy_keys, sizeof(dummy_keys)) != 0) printf("  - ERROR: Key data mismatch!\n");
            break;
        }
        case CTE_PEEK_TYPE_SIG_VECTOR_SIZE_1:
        {
            const uint8_t *data = cte_decoder_read_signature_vector_data(dec);
            printf("  - Read Sig Vector. New Pos: %zu\n", dec->position);
            if (memcmp(data, dummy_sig, sizeof(dummy_sig)) != 0) printf("  - ERROR: Sig data mismatch!\n");
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_VECTOR_INDEX:
        {
            uint8_t index = cte_decoder_read_ixdata_vector_index(dec);
            printf("  - Read IxData Vector Index: %u. New Pos: %zu\n", index, dec->position);
            if (ix_legacy_count == 0 && index != 1) printf("  - ERROR: First index mismatch!\n");
            if (ix_legacy_count == 1 && index != 0) printf("  - ERROR: Second index mismatch!\n");
            ix_legacy_count++;
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_ULEB128:
        {
            uint64_t val = cte_decoder_read_ixdata_uleb128(dec);
            printf("  - Read IxData ULEB128: %llu. New Pos: %zu\n", (unsigned long long)val, dec->position);
            if (val != uleb_val_enc) printf("  - ERROR: ULEB128 value mismatch!\n");
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_SLEB128:
        {
            int64_t val = cte_decoder_read_ixdata_sleb128(dec);
            printf("  - Read IxData SLEB128: %lld. New Pos: %zu\n", (long long)val, dec->position);
            if (val != sleb_val_enc) printf("  - ERROR: SLEB128 value mismatch!\n");
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_INT8:
        {
            int8_t val = cte_decoder_read_ixdata_int8(dec);
            printf("  - Read IxData Int8: %d. New Pos: %zu\n", val, dec->position);
            if (val != i8_val_enc) printf("  - ERROR: Int8 value mismatch!\n");
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_INT16:
        {
            int16_t val = cte_decoder_read_ixdata_int16(dec);
            printf("  - Read IxData Int16: %d. New Pos: %zu\n", val, dec->position);
            if (val != i16_val_enc) printf("  - ERROR: Int16 value mismatch!\n");
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_INT32:
        {
            int32_t val = cte_decoder_read_ixdata_int32(dec);
            printf("  - Read IxData Int32: %d. New Pos: %zu\n", val, dec->position);
            if (val != i32_val_enc) printf("  - ERROR: Int32 value mismatch!\n");
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_UINT8:
        {
            uint8_t val = cte_decoder_read_ixdata_uint8(dec);
            printf("  - Read IxData Uint8: %u. New Pos: %zu\n", val, dec->position);
            if (val != u8_val_enc) printf("  - ERROR: Uint8 value mismatch!\n");
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_UINT16:
        {
            uint16_t val = cte_decoder_read_ixdata_uint16(dec);
            printf("  - Read IxData Uint16: %u. New Pos: %zu\n", val, dec->position);
            if (val != u16_val_enc) printf("  - ERROR: Uint16 value mismatch!\n");
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_UINT32:
        {
            uint32_t val = cte_decoder_read_ixdata_uint32(dec);
            printf("  - Read IxData Uint32: %u. New Pos: %zu\n", val, dec->position);
            if (val != u32_val_enc) printf("  - ERROR: Uint32 value mismatch!\n");
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_UINT64:
        {
            uint64_t val = cte_decoder_read_ixdata_uint64(dec);
            printf("  - Read IxData Uint64: %llu. New Pos: %zu\n", (unsigned long long)val, dec->position);
            if (val != u64_val_enc) printf("  - ERROR: Uint64 value mismatch!\n");
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_FLOAT32:
        {
            float val = cte_decoder_read_ixdata_float32(dec);
            printf("  - Read IxData Float32: %f. New Pos: %zu\n", val, dec->position);
            if (val != f32_val_enc) printf("  - ERROR: Float32 value mismatch!\n");
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_FLOAT64:
        {
            double val = cte_decoder_read_ixdata_float64(dec);
            printf("  - Read IxData Float64: %f. New Pos: %zu\n", val, dec->position);
            if (val != f64_val_enc) printf("  - ERROR: Float64 value mismatch!\n");
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_CONST_TRUE:
        case CTE_PEEK_TYPE_IXDATA_CONST_FALSE:
        {
            bool val = cte_decoder_read_ixdata_boolean(dec);
            printf("  - Read IxData Boolean: %s. New Pos: %zu\n", val ? "true" : "false", dec->position);
            if (ix_const_count == 0 && val != true) printf("  - ERROR: First boolean mismatch!\n");
            if (ix_const_count == 1 && val != false) printf("  - ERROR: Second boolean mismatch!\n");
            ix_const_count++;
            break;
        }
        case CTE_PEEK_TYPE_VECTOR_SHORT:
        {
            const uint8_t *data = cte_decoder_read_vector_data_payload(dec);
            printf("  - Read Vector Data. New Pos: %zu\n", dec->position);
            if (memcmp(data, short_cmd_enc, short_len_enc) != 0) printf("  - ERROR: Short data mismatch!\n");
            break;
        }
        case CTE_PEEK_TYPE_VECTOR_EXTENDED:
        {
            const uint8_t *data = cte_decoder_read_vector_data_payload(dec);
            printf("  - Read Vector Data. New Pos: %zu\n", dec->position);
            if (memcmp(data, long_cmd_enc, long_len_enc) != 0) printf("  - ERROR: Long data mismatch!\n");
            break;
        }
        default:
            printf("ERROR: Unknown type %d at position %zu. Aborting test.\n", type, current_pos);
            goto end_loop;
        }
    }

end_loop:;
    if (dec->position != encoded_size)
    {
        printf("\nERROR: Final decoder position (%zu) does not match encoded size (%zu)!\n", dec->position, encoded_size);
    }
    else
    {
        printf("\nSuccessfully decoded all fields. Final position matches encoded size.\n");
    }

    printf("\n--- Test Complete ---\n");
    return 0;
}
