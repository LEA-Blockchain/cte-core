#include "cte.h"
#include <stdlea.h>

/**
 * @brief Gets the size in bytes of a public key for a given entry size code.
 * @param size_code The 2-bit size code from the vector header.
 * @return The size of the public key in bytes.
 * @note This function will abort via `lea_abort` if an invalid size code is provided.
 */
LEA_EXPORT(get_public_key_size)
size_t get_public_key_size(uint8_t size_code)
{
    switch (size_code)
    {
    case CTE_VECTOR_ENTRY_SIZE_CODE_0:
        return CTE_PUBKEY_SIZE_CODE_0;
    case CTE_VECTOR_ENTRY_SIZE_CODE_1:
        return CTE_PUBKEY_SIZE_CODE_1;
    case CTE_VECTOR_ENTRY_SIZE_CODE_2:
        return CTE_PUBKEY_SIZE_CODE_2;
    default:
        lea_abort("Invalid public key size code");
    }
}

/**
 * @brief Gets the size in bytes of a signature vector item for a given entry size code.
 * @param size_code The 2-bit size code from the vector header.
 * @return The size of the signature item in bytes.
 * @note This function will abort via `lea_abort` if an invalid size code is provided.
 */
LEA_EXPORT(get_signature_item_size)
size_t get_signature_item_size(uint8_t size_code)
{
    switch (size_code)
    {
    case CTE_VECTOR_ENTRY_SIZE_CODE_0:
        return CTE_SIGNATURE_SIZE_CODE_0;
    case CTE_VECTOR_ENTRY_SIZE_CODE_1:
        return CTE_SIGNATURE_SIZE_CODE_1;
    case CTE_VECTOR_ENTRY_SIZE_CODE_2:
        return CTE_SIGNATURE_SIZE_CODE_2;
    case CTE_VECTOR_ENTRY_SIZE_CODE_3:
        return CTE_SIGNATURE_SIZE_CODE_3;
    default:
        lea_abort("Invalid signature size code");
    }
}
