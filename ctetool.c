#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include "encoder.h"
#include "decoder.h"

#define DEFAULT_BUFFER_SIZE 4096
#define MAX_BUFFER_SIZE 16777216 // 16 MB

/**
 * @brief Prints the command-line usage instructions for the tool.
 */
void print_usage() {
    printf("Usage: ctetool <command> [options] [args...]\n\n");
    printf("Commands:\n");
    printf("  write   Create a CTE file from a sequence of fields.\n");
    printf("  read    Read a CTE file and print its contents.\n");
    printf("  help    Show this help message.\n\n");
    printf("Options for 'write' and 'read':\n");
    printf("  -b <size>   Use a buffer of the specified size in bytes (max %dMB).\n\n", MAX_BUFFER_SIZE / (1024 * 1024));
    printf("Options for 'write':\n");
    printf("  -o <file>   Write to the specified file instead of stdout.\n\n");
    printf("Options for 'read':\n");
    printf("  -i <file>   Read from the specified file instead of stdin.\n\n");
    printf("Field Formats for 'write':\n");
    printf("  Type:Value                                Examples:\n");
    printf("  ----------------------------------------------------------------\n");
    printf("  uint8:<val>      (val: 0-255 or 0x00-0xFF)  uint8:255, uint8:0xFF\n");
    printf("  uint16:<val>     (val: dec or hex)          uint16:65535\n");
    printf("  uint32:<val>     (val: dec or hex)          uint32:0xABCDEF12\n");
    printf("  uint64:<val>     (val: dec or hex)          uint64:1234567890\n");
    printf("  int8:<val>       (val: -128-127 or hex)     int8:-100\n");
    printf("  int16:<val>      (val: dec or hex)          int16:-30000\n");
    printf("  int32:<val>      (val: dec or hex)          int32:0x-FFFF\n");
    printf("  int64:<val>      (val: dec or hex)          int64:-1234567890\n");
    printf("  uleb:<val>       (val: dec or hex)          uleb:123456\n");
    printf("  sleb:<val>       (val: dec or hex)          sleb:-78910\n");
    printf("  float:<val>                                 float:3.14159\n");
    printf("  double:<val>                                double:1.23456789\n");
    printf("  bool:<true|false>                           bool:true\n");
    printf("  index:<0-15>                                index:5\n");
    printf("  vec:<hex_string>                            vec:AABBCCDD\n");
    printf("  pk-vec-[size]:<hex_string>                  pk-vec-32:112233FF\n");
    printf("  sig-vec-[size]:<hex_string>                 sig-vec-64:AABBCCEE\n");
    printf("    [size] can be: 32, 64, 128, 29792\n");
}

#ifndef ENV_WASM_MVP
/**
 * @brief Dummy implementation of the host data handler for native builds.
 */
void __cte_data_handler(int type, const void *data, size_t size)
{
    // This is a stub for the native test build. It does nothing.
    (void)type;
    (void)data;
    (void)size;
}
#endif

/**
 * @brief Converts a hexadecimal string to a byte array.
 * @param hex_str The input string of hexadecimal characters.
 * @param byte_array The output buffer to store the converted bytes.
 * @param max_bytes The maximum number of bytes to write to the output buffer.
 * @return The number of bytes written, or 0 on error.
 */
size_t hex_string_to_bytes(const char *hex_str, uint8_t *byte_array, size_t max_bytes) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) return 0; // Invalid hex string
    size_t byte_len = len / 2;
    if (byte_len > max_bytes) return 0; // Too long

    for (size_t i = 0; i < byte_len; i++) {
        sscanf(hex_str + 2 * i, "%2hhx", &byte_array[i]);
    }
    return byte_len;
}

/**
 * @brief Handles the 'write' command for the CTE tool.
 * @param argc The argument count from main.
 * @param argv The argument vector from main.
 * @note This function exits on error.
 */
void do_write(int argc, char *argv[]) {
    const char *output_file = NULL;
    size_t buffer_size = DEFAULT_BUFFER_SIZE;
    int first_field_index = 2;

    // Parse options
    while (first_field_index < argc && argv[first_field_index][0] == '-') {
        if (strcmp(argv[first_field_index], "-o") == 0) {
            if (first_field_index + 1 >= argc) {
                fprintf(stderr, "Error: -o option requires a filename.\n");
                exit(1);
            }
            output_file = argv[first_field_index + 1];
            first_field_index += 2;
        } else if (strcmp(argv[first_field_index], "-b") == 0) {
            if (first_field_index + 1 >= argc) {
                fprintf(stderr, "Error: -b option requires a size.\n");
                exit(1);
            }
            buffer_size = (size_t)strtoul(argv[first_field_index + 1], NULL, 0);
            if (buffer_size == 0 || buffer_size > MAX_BUFFER_SIZE) {
                fprintf(stderr, "Error: Invalid buffer size. Must be > 0 and <= %d.\n", MAX_BUFFER_SIZE);
                exit(1);
            }
            first_field_index += 2;
        } else {
            fprintf(stderr, "Error: Unknown option '%s'.\n", argv[first_field_index]);
            exit(1);
        }
    }

    if (argc <= first_field_index) {
        fprintf(stderr, "Error: No fields provided for 'write' command.\n");
        exit(1);
    }

    cte_encoder_t *enc = cte_encoder_init(buffer_size);

    for (int i = first_field_index; i < argc; i++) {
        char *arg = strdup(argv[i]);
        if (!arg) {
            fprintf(stderr, "Error: Out of memory.\n");
            exit(1);
        }
        char *colon = strchr(arg, ':');
        if (!colon) {
            fprintf(stderr, "Error: Invalid field format '%s'. Expected 'type:value'.\n", arg);
            free(arg);
            exit(1);
        }
        *colon = '\0'; // Split the string
        const char *type = arg;
        const char *value = colon + 1;
        char *endptr;

        errno = 0;

        if (strcmp(type, "uint8") == 0) {
            unsigned long val = strtoul(value, &endptr, 0);
            if (*endptr != '\0' || errno != 0 || val > UINT8_MAX) {
                fprintf(stderr, "Error: Invalid value for uint8: %s\n", value);
                exit(1);
            }
            cte_encoder_write_ixdata_uint8(enc, (uint8_t)val);
        } else if (strcmp(type, "uint16") == 0) {
            unsigned long val = strtoul(value, &endptr, 0);
            if (*endptr != '\0' || errno != 0 || val > UINT16_MAX) {
                fprintf(stderr, "Error: Invalid value for uint16: %s\n", value);
                exit(1);
            }
            cte_encoder_write_ixdata_uint16(enc, (uint16_t)val);
        } else if (strcmp(type, "uint32") == 0) {
            unsigned long val = strtoul(value, &endptr, 0);
            if (*endptr != '\0' || errno != 0 || val > UINT32_MAX) {
                fprintf(stderr, "Error: Invalid value for uint32: %s\n", value);
                exit(1);
            }
            cte_encoder_write_ixdata_uint32(enc, (uint32_t)val);
        } else if (strcmp(type, "uint64") == 0) {
            unsigned long long val = strtoull(value, &endptr, 0);
            if (*endptr != '\0' || errno != 0) {
                fprintf(stderr, "Error: Invalid value for uint64: %s\n", value);
                exit(1);
            }
            cte_encoder_write_ixdata_uint64(enc, val);
        } else if (strcmp(type, "int8") == 0) {
            long val = strtol(value, &endptr, 0);
            if (*endptr != '\0' || errno != 0 || val < INT8_MIN || val > INT8_MAX) {
                fprintf(stderr, "Error: Invalid value for int8: %s\n", value);
                exit(1);
            }
            cte_encoder_write_ixdata_int8(enc, (int8_t)val);
        } else if (strcmp(type, "int16") == 0) {
            long val = strtol(value, &endptr, 0);
            if (*endptr != '\0' || errno != 0 || val < INT16_MIN || val > INT16_MAX) {
                fprintf(stderr, "Error: Invalid value for int16: %s\n", value);
                exit(1);
            }
            cte_encoder_write_ixdata_int16(enc, (int16_t)val);
        } else if (strcmp(type, "int32") == 0) {
            long val = strtol(value, &endptr, 0);
            if (*endptr != '\0' || errno != 0 || val < INT32_MIN || val > INT32_MAX) {
                fprintf(stderr, "Error: Invalid value for int32: %s\n", value);
                exit(1);
            }
            cte_encoder_write_ixdata_int32(enc, (int32_t)val);
        } else if (strcmp(type, "int64") == 0) {
            long long val = strtoll(value, &endptr, 0);
            if (*endptr != '\0' || errno != 0) {
                fprintf(stderr, "Error: Invalid value for int64: %s\n", value);
                exit(1);
            }
            cte_encoder_write_ixdata_int64(enc, val);
        } else if (strcmp(type, "uleb") == 0) {
            unsigned long long val = strtoull(value, &endptr, 0);
            if (*endptr != '\0' || errno != 0) {
                fprintf(stderr, "Error: Invalid value for uleb: %s\n", value);
                exit(1);
            }
            cte_encoder_write_ixdata_uleb128(enc, val);
        } else if (strcmp(type, "sleb") == 0) {
            long long val = strtoll(value, &endptr, 0);
            if (*endptr != '\0' || errno != 0) {
                fprintf(stderr, "Error: Invalid value for sleb: %s\n", value);
                exit(1);
            }
            cte_encoder_write_ixdata_sleb128(enc, val);
        } else if (strcmp(type, "float") == 0) {
            float val = strtof(value, &endptr);
            if (*endptr != '\0' || errno != 0) {
                fprintf(stderr, "Error: Invalid value for float: %s\n", value);
                exit(1);
            }
            cte_encoder_write_ixdata_float32(enc, val);
        } else if (strcmp(type, "double") == 0) {
            double val = strtod(value, &endptr);
            if (*endptr != '\0' || errno != 0) {
                fprintf(stderr, "Error: Invalid value for double: %s\n", value);
                exit(1);
            }
            cte_encoder_write_ixdata_float64(enc, val);
        } else if (strcmp(type, "bool") == 0) {
            if (strcmp(value, "true") != 0 && strcmp(value, "false") != 0) {
                fprintf(stderr, "Error: Invalid value for bool: %s\n", value);
                exit(1);
            }
            cte_encoder_write_ixdata_boolean(enc, strcmp(value, "true") == 0);
        } else if (strcmp(type, "index") == 0) {
            unsigned long val = strtoul(value, &endptr, 0);
            if (*endptr != '\0' || errno != 0 || val > 15) {
                fprintf(stderr, "Error: Invalid value for index: %s\n", value);
                exit(1);
            }
            cte_encoder_write_ixdata_vector_index(enc, (uint8_t)val);
        } else if (strcmp(type, "vec") == 0) {
            uint8_t buffer[DEFAULT_BUFFER_SIZE];
            size_t len = hex_string_to_bytes(value, buffer, DEFAULT_BUFFER_SIZE);
            if (len == 0 && strlen(value) > 0) {
                fprintf(stderr, "Error: Invalid hex string for vec: %s\n", value);
                exit(1);
            }
            void *ptr = cte_encoder_begin_vector_data(enc, len);
            memcpy(ptr, buffer, len);
        } else {
            fprintf(stderr, "Error: Unknown field type '%s'.\n", type);
            free(arg);
            exit(1);
        }
        free(arg);
    }

    const uint8_t *data = cte_encoder_get_data(enc);
    size_t size = cte_encoder_get_size(enc);

    if (output_file) {
        FILE *fp = fopen(output_file, "wb");
        if (!fp) {
            perror("Error opening output file");
            exit(1);
        }
        fwrite(data, 1, size, fp);
        fclose(fp);
        printf("Wrote %zu bytes to %s\n", size, output_file);
    } else {
        fwrite(data, 1, size, stdout);
    }
}

/**
 * @brief Handles the 'read' command for the CTE tool.
 * @param argc The argument count from main.
 * @param argv The argument vector from main.
 * @note This function exits on error.
 */
void do_read(int argc, char *argv[]) {
    const char *input_file = NULL;
    size_t buffer_size = DEFAULT_BUFFER_SIZE;
    FILE *fp = stdin;
    int first_arg_index = 2;

    while (first_arg_index < argc && argv[first_arg_index][0] == '-') {
        if (strcmp(argv[first_arg_index], "-i") == 0) {
            if (first_arg_index + 1 >= argc) {
                fprintf(stderr, "Error: -i option requires a filename.\n");
                exit(1);
            }
            input_file = argv[first_arg_index + 1];
            fp = fopen(input_file, "rb");
            if (!fp) {
                perror("Error opening input file");
                exit(1);
            }
            first_arg_index += 2;
        } else if (strcmp(argv[first_arg_index], "-b") == 0) {
            if (first_arg_index + 1 >= argc) {
                fprintf(stderr, "Error: -b option requires a size.\n");
                exit(1);
            }
            buffer_size = (size_t)strtoul(argv[first_arg_index + 1], NULL, 0);
            if (buffer_size == 0 || buffer_size > MAX_BUFFER_SIZE) {
                fprintf(stderr, "Error: Invalid buffer size. Must be > 0 and <= %d.\n", MAX_BUFFER_SIZE);
                exit(1);
            }
            first_arg_index += 2;
        } else {
            fprintf(stderr, "Error: Unknown option '%s'.\n", argv[first_arg_index]);
            exit(1);
        }
    }

    uint8_t *buffer = malloc(buffer_size);
    if (!buffer) {
        fprintf(stderr, "Error: Failed to allocate buffer of size %zu.\n", buffer_size);
        exit(1);
    }
    
    size_t total_read = 0;
    size_t bytes_read;

    while ((bytes_read = fread(buffer + total_read, 1, buffer_size - total_read, fp)) > 0) {
        total_read += bytes_read;
        if (total_read >= buffer_size && !feof(fp)) {
            fprintf(stderr, "Error: Input data exceeds buffer size of %zu bytes.\n", buffer_size);
            free(buffer);
            exit(1);
        }
    }

    if (input_file) {
        fclose(fp);
    }

    if (total_read == 0) {
        fprintf(stderr, "Error: No data read from input.\n");
        free(buffer);
        exit(1);
    }

    cte_decoder_t *dec = cte_decoder_init(total_read);
    uint8_t *load_ptr = cte_decoder_load(dec);
    memcpy(load_ptr, buffer, total_read);
    free(buffer);

    printf("Reading from %s (%zu bytes).....\n", input_file ? input_file : "stdin", total_read);
    printf("--------------------------------------\n");

    while (dec->position < dec->size) {
        int type = cte_decoder_peek_type(dec);
        if (type == CTE_PEEK_EOF) {
            break;
        }

        printf("Type: %d, ", type);

        switch (type) {
            case CTE_PEEK_TYPE_PK_VECTOR_SIZE_0:
            case CTE_PEEK_TYPE_PK_VECTOR_SIZE_1:
            case CTE_PEEK_TYPE_PK_VECTOR_SIZE_2:
            case CTE_PEEK_TYPE_PK_VECTOR_SIZE_3:
                {
                    cte_decoder_read_public_key_vector_data(dec);
                    size_t count = cte_decoder_get_last_vector_count(dec);
                    printf("Public Key Vector, Count: %zu\n", count);
                    break;
                }
            case CTE_PEEK_TYPE_SIG_VECTOR_SIZE_0:
            case CTE_PEEK_TYPE_SIG_VECTOR_SIZE_1:
            case CTE_PEEK_TYPE_SIG_VECTOR_SIZE_2:
            case CTE_PEEK_TYPE_SIG_VECTOR_SIZE_3:
                {
                    cte_decoder_read_signature_vector_data(dec);
                    size_t count = cte_decoder_get_last_vector_count(dec);
                    printf("Signature Vector, Count: %zu\n", count);
                    break;
                }
            case CTE_PEEK_TYPE_IXDATA_VECTOR_INDEX:
                printf("IxData Vector Index, Value: %u\n", cte_decoder_read_ixdata_vector_index(dec));
                break;
            case CTE_PEEK_TYPE_IXDATA_VARINT_ZERO:
                cte_decoder_read_ixdata_varint_zero(dec);
                printf("IxData Varint Zero\n");
                break;
            case CTE_PEEK_TYPE_IXDATA_ULEB128:
                printf("IxData ULEB128, Value: %llu\n", (unsigned long long)cte_decoder_read_ixdata_uleb128(dec));
                break;
            case CTE_PEEK_TYPE_IXDATA_SLEB128:
                printf("IxData SLEB128, Value: %lld\n", (long long)cte_decoder_read_ixdata_sleb128(dec));
                break;
            case CTE_PEEK_TYPE_IXDATA_INT8:
                printf("IxData int8, Value: %d\n", cte_decoder_read_ixdata_int8(dec));
                break;
            case CTE_PEEK_TYPE_IXDATA_INT16:
                printf("IxData int16, Value: %d\n", cte_decoder_read_ixdata_int16(dec));
                break;
            case CTE_PEEK_TYPE_IXDATA_INT32:
                printf("IxData int32, Value: %d\n", cte_decoder_read_ixdata_int32(dec));
                break;
            case CTE_PEEK_TYPE_IXDATA_INT64:
                printf("IxData int64, Value: %lld\n", (long long)cte_decoder_read_ixdata_int64(dec));
                break;
            case CTE_PEEK_TYPE_IXDATA_UINT8:
                printf("IxData uint8, Value: %u\n", cte_decoder_read_ixdata_uint8(dec));
                break;
            case CTE_PEEK_TYPE_IXDATA_UINT16:
                printf("IxData uint16, Value: %u\n", cte_decoder_read_ixdata_uint16(dec));
                break;
            case CTE_PEEK_TYPE_IXDATA_UINT32:
                printf("IxData uint32, Value: %u\n", cte_decoder_read_ixdata_uint32(dec));
                break;
            case CTE_PEEK_TYPE_IXDATA_UINT64:
                printf("IxData uint64, Value: %llu\n", (unsigned long long)cte_decoder_read_ixdata_uint64(dec));
                break;
            case CTE_PEEK_TYPE_IXDATA_FLOAT32:
                printf("IxData float32, Value: %f\n", cte_decoder_read_ixdata_float32(dec));
                break;
            case CTE_PEEK_TYPE_IXDATA_FLOAT64:
                printf("IxData float64, Value: %f\n", cte_decoder_read_ixdata_float64(dec));
                break;
            case CTE_PEEK_TYPE_IXDATA_CONST_FALSE:
            case CTE_PEEK_TYPE_IXDATA_CONST_TRUE:
                printf("IxData boolean, Value: %s\n", cte_decoder_read_ixdata_boolean(dec) ? "true" : "false");
                break;
            case CTE_PEEK_TYPE_VECTOR_SHORT:
            case CTE_PEEK_TYPE_VECTOR_EXTENDED:
                {
                    cte_decoder_read_vector_data_payload(dec);
                    size_t len = cte_decoder_get_last_vector_data_payload_length(dec);
                    printf("Vector Data, Length: %zu\n", len);
                    break;
                }
            default:
                fprintf(stderr, "Read for type %d not implemented yet. Aborting.\n", type);
                exit(1);
        }
    }

    printf("--------------------------------------\n");
    printf("Successfully decoded all fields.\n");
}

/**
 * @brief Main entry point for the CTE command-line tool.
 * @param argc The number of command-line arguments.
 * @param argv An array of command-line argument strings.
 * @return 0 on success, 1 on error.
 */
int main(int argc, char *argv[]) {
    if (argc < 2 || strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage();
        return 0;
    }

    const char *command = argv[1];

    if (strcmp(command, "write") == 0) {
        do_write(argc, argv);
    } else if (strcmp(command, "read") == 0) {
        do_read(argc, argv);
    } else {
        fprintf(stderr, "Error: Unknown command '%s'\n", command);
        print_usage();
        return 1;
    }

    return 0;
}
