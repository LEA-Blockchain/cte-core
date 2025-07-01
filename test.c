#include "decoder.h"
#include "encoder.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define BUFFER_SIZE 2048

/**
 * @brief Gets a human-readable name for a given tag and subtype combination.
 * @param tag The main 2-bit tag of the field.
 * @param subtype The subtype code, whose meaning depends on the tag.
 * @return A const character string representing the name.
 */
const char *get_subtype_name(int tag, int subtype)
{
    switch (tag)
    {
    case CTE_TAG_PUBLIC_KEY_LIST:
    case CTE_TAG_SIGNATURE_LIST:
        switch (subtype)
        {
        case CTE_CRYPTO_TYPE_ED25519:
            return "ED25519";
        case CTE_CRYPTO_TYPE_SLH_DSA_128F:
            return "SLH_DSA_128F";
        default:
            return "Unknown Crypto";
        }
    case CTE_TAG_IXDATA_FIELD:
        switch (subtype)
        {
        case CTE_IXDATA_SUBTYPE_LEGACY_INDEX:
            return "Legacy Index";
        case CTE_IXDATA_SUBTYPE_VARINT:
            return "Varint";
        case CTE_IXDATA_SUBTYPE_FIXED:
            return "Fixed";
        case CTE_IXDATA_SUBTYPE_CONSTANT:
            return "Constant";
        default:
            return "Unknown IxData";
        }
    case CTE_TAG_COMMAND_DATA:
        switch (subtype)
        {
        case 0:
            return "Short Format";
        case 1:
            return "Extended Format";
        default:
            return "Unknown Format";
        }
    default:
        return "Unknown Tag";
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
    uint8_t key_type_enc = CTE_CRYPTO_TYPE_ED25519;
    uint8_t dummy_keys[2 * CTE_PUBKEY_SIZE_ED25519];
    for (size_t i = 0; i < sizeof(dummy_keys); ++i)
        dummy_keys[i] = (uint8_t)(0xAA + i);
    void *key_ptr = cte_encoder_begin_public_key_list(enc, key_count_enc, key_type_enc);
    memcpy(key_ptr, dummy_keys, sizeof(dummy_keys));
    printf("  - Public Key List (Type: %u, Count: %u)\n", key_type_enc, key_count_enc);

    cte_encoder_write_ixdata_index_reference(enc, 1);
    printf("  - IxData Legacy Index (1)\n");

    uint8_t sig_count_enc = 1;
    uint8_t sig_type_enc = CTE_CRYPTO_TYPE_SLH_DSA_128F;
    uint8_t dummy_sig_hash[CTE_SIGNATURE_HASH_SIZE_PQC];
    for (size_t i = 0; i < sizeof(dummy_sig_hash); ++i)
        dummy_sig_hash[i] = (uint8_t)(0xBB + i);
    void *sig_ptr = cte_encoder_begin_signature_list(enc, sig_count_enc, sig_type_enc);
    memcpy(sig_ptr, dummy_sig_hash, sizeof(dummy_sig_hash));
    printf("  - Signature List (Type: %u, Count: %u)\n", sig_type_enc, sig_count_enc);

    cte_encoder_write_ixdata_index_reference(enc, 0);
    printf("  - IxData Legacy Index (0)\n");

    uint64_t uleb_val_enc = 123456;
    cte_encoder_write_ixdata_uleb128(enc, uleb_val_enc);
    printf("  - IxData ULEB128 (%llu)\n", (unsigned long long)uleb_val_enc);

    int64_t sleb_val_enc = -78910;
    cte_encoder_write_ixdata_sleb128(enc, sleb_val_enc);
    printf("  - IxData SLEB128 (%lld)\n", (long long)sleb_val_enc);

    int32_t i32_val_enc = -1000;
    cte_encoder_write_ixdata_int32(enc, i32_val_enc);
    printf("  - IxData Int32 (%d)\n", i32_val_enc);

    uint64_t u64_val_enc = 9876543210ULL;
    cte_encoder_write_ixdata_uint64(enc, u64_val_enc);
    printf("  - IxData Uint64 (%llu)\n", (unsigned long long)u64_val_enc);

    float f32_val_enc = 3.14159f;
    cte_encoder_write_ixdata_float32(enc, f32_val_enc);
    printf("  - IxData Float32 (%f)\n", f32_val_enc);

    cte_encoder_write_ixdata_boolean(enc, true);
    printf("  - IxData Boolean (true)\n");
    cte_encoder_write_ixdata_boolean(enc, false);
    printf("  - IxData Boolean (false)\n");

    const char *short_cmd_enc = "Short payload";
    size_t short_len_enc = strlen(short_cmd_enc);
    void *cmd_ptr_short = cte_encoder_begin_command_data(enc, short_len_enc);
    memcpy(cmd_ptr_short, short_cmd_enc, short_len_enc);
    printf("  - Command Data (Short, Len: %zu)\n", short_len_enc);

    char long_cmd_enc[200];
    memset(long_cmd_enc, 'L', sizeof(long_cmd_enc));
    long_cmd_enc[199] = '\0';
    size_t long_len_enc = 150;
    void *cmd_ptr_long = cte_encoder_begin_command_data(enc, long_len_enc);
    memcpy(cmd_ptr_long, long_cmd_enc, long_len_enc);
    printf("  - Command Data (Extended, Len: %zu)\n", long_len_enc);

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
        int tag = cte_decoder_peek_tag(dec);
        int subtype = cte_decoder_peek_subtype(dec);

        printf("\nPos: %-3zu -> Peeked Tag: %02X, Subtype: %d (%s)\n",
               current_pos, tag, subtype, get_subtype_name(tag, subtype));

        switch (tag)
        {
        case CTE_TAG_PUBLIC_KEY_LIST:
        {
            uint8_t count = cte_decoder_peek_public_key_list_count(dec);
            const uint8_t *data = cte_decoder_read_public_key_list_data(dec);
            printf("  - Read PubKey List (Count: %u). New Pos: %zu\n", count, dec->position);
            if (count != key_count_enc) printf("  - ERROR: Key count mismatch!\n");
            if (subtype != key_type_enc) printf("  - ERROR: Key type mismatch!\n");
            if (memcmp(data, dummy_keys, sizeof(dummy_keys)) != 0) printf("  - ERROR: Key data mismatch!\n");
            break;
        }
        case CTE_TAG_SIGNATURE_LIST:
        {
            uint8_t count = cte_decoder_peek_signature_list_count(dec);
            const uint8_t *data = cte_decoder_read_signature_list_data(dec);
            printf("  - Read Sig List (Count: %u). New Pos: %zu\n", count, dec->position);
            if (count != sig_count_enc) printf("  - ERROR: Sig count mismatch!\n");
            if (subtype != sig_type_enc) printf("  - ERROR: Sig type mismatch!\n");
            if (memcmp(data, dummy_sig_hash, sizeof(dummy_sig_hash)) != 0) printf("  - ERROR: Sig data mismatch!\n");
            break;
        }
        case CTE_TAG_IXDATA_FIELD:
        {
            int header_byte = dec->data[dec->position];
            uint8_t detail_code = (header_byte >> 2) & 0x0F;

            switch (subtype)
            {
            case CTE_IXDATA_SUBTYPE_LEGACY_INDEX:
            {
                uint8_t index = cte_decoder_read_ixdata_index_reference(dec);
                printf("  - Read IxData Legacy Index: %u. New Pos: %zu\n", index, dec->position);
                if (ix_legacy_count == 0 && index != 1) printf("  - ERROR: First index mismatch!\n");
                if (ix_legacy_count == 1 && index != 0) printf("  - ERROR: Second index mismatch!\n");
                ix_legacy_count++;
                break;
            }
            case CTE_IXDATA_SUBTYPE_VARINT:
                if (detail_code == CTE_IXDATA_VARINT_ENC_ULEB128)
                {
                    uint64_t val = cte_decoder_read_ixdata_uleb128(dec);
                    printf("  - Read IxData ULEB128: %llu. New Pos: %zu\n", (unsigned long long)val, dec->position);
                    if (val != uleb_val_enc) printf("  - ERROR: ULEB128 value mismatch!\n");
                }
                else if (detail_code == CTE_IXDATA_VARINT_ENC_SLEB128)
                {
                    int64_t val = cte_decoder_read_ixdata_sleb128(dec);
                    printf("  - Read IxData SLEB128: %lld. New Pos: %zu\n", (long long)val, dec->position);
                    if (val != sleb_val_enc) printf("  - ERROR: SLEB128 value mismatch!\n");
                }
                break;
            case CTE_IXDATA_SUBTYPE_FIXED:
                if (detail_code == CTE_IXDATA_FIXED_TYPE_INT32)
                {
                    int32_t val = cte_decoder_read_ixdata_int32(dec);
                    printf("  - Read IxData Int32: %d. New Pos: %zu\n", val, dec->position);
                    if (val != i32_val_enc) printf("  - ERROR: Int32 value mismatch!\n");
                }
                else if (detail_code == CTE_IXDATA_FIXED_TYPE_UINT64)
                {
                    uint64_t val = cte_decoder_read_ixdata_uint64(dec);
                    printf("  - Read IxData Uint64: %llu. New Pos: %zu\n", (unsigned long long)val, dec->position);
                    if (val != u64_val_enc) printf("  - ERROR: Uint64 value mismatch!\n");
                }
                else if (detail_code == CTE_IXDATA_FIXED_TYPE_FLOAT32)
                {
                    float val = cte_decoder_read_ixdata_float32(dec);
                    printf("  - Read IxData Float32: %f. New Pos: %zu\n", val, dec->position);
                    if (val != f32_val_enc) printf("  - ERROR: Float32 value mismatch!\n");
                }
                break;
            case CTE_IXDATA_SUBTYPE_CONSTANT:
            {
                bool val = cte_decoder_read_ixdata_boolean(dec);
                printf("  - Read IxData Boolean: %s. New Pos: %zu\n", val ? "true" : "false", dec->position);
                if (ix_const_count == 0 && val != true) printf("  - ERROR: First boolean mismatch!\n");
                if (ix_const_count == 1 && val != false) printf("  - ERROR: Second boolean mismatch!\n");
                ix_const_count++;
                break;
            }
            }
            break;
        }
        case CTE_TAG_COMMAND_DATA:
        {
            size_t len = cte_decoder_peek_command_data_length(dec);
            const uint8_t *data = cte_decoder_read_command_data_payload(dec);
            printf("  - Read Command Data (Len: %zu). New Pos: %zu\n", len, dec->position);
            if (subtype == 0) // Short
            {
                printf("    - Decoded Short Payload: '%.*s'\n", (int)len, data);
                if (len != short_len_enc) printf("  - ERROR: Short length mismatch!\n");
                if (memcmp(data, short_cmd_enc, len) != 0) printf("  - ERROR: Short data mismatch!\n");
            }
            else // Extended
            {
                printf("    - Decoded Long Payload: '%.*s'\n", (int)len, data);
                if (len != long_len_enc) printf("  - ERROR: Long length mismatch!\n");
                if (memcmp(data, long_cmd_enc, len) != 0) printf("  - ERROR: Long data mismatch!\n");
            }
            break;
        }
        default:
            printf("ERROR: Unknown tag %02X at position %zu. Aborting test.\n", tag, current_pos);
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
