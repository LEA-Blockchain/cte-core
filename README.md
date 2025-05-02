# cte-core: Compact Transaction Encoding for Lea

A streamlined, verifiable Compact Transaction Encoding (CTE) implementation, specifically tailored to meet the core requirements of the Lea blockchain.

## Purpose

This repository (`cte-core`) provides a **secure and easily auditable codebase** containing the essential Compact Transaction Encoding (CTE) features required to operate the LEA Blockchain.

This project originated as a minimal, stable subset of a broader CTE implementation. It has been established as a separate repository to focus exclusively on providing a secure foundation for LEA.

By focusing on necessary functionality, we aim to:
* Reduce the attack surface.
* Simplify security auditing and verification.
* Provide a stable and reliable CTE implementation for the LEA environment.

## Included Features (Scope for Audit)

This implementation focuses on the core CTE functionalities deemed essential for the LEA Blockchain:

1.  **Core CTE v1.0 ([CTE-1.md](https://github.com/LEA-Blockchain/serialization-codecs/blob/main/cte/CTE-1.md)) Structure:**
    * Version Byte (`0x01`), Max Transaction Size (1232 bytes).
    * Field Tags: `00` (Public Key List), `01` (Signature List), `10` (IxData Field), `11` (Command Data).
    * Command Data: Support for both Short (`L <= 31`) and Extended (`32 <= L <= 1197`) formats.

2.  **LIP-0001: IxData Field ([LIP-0001](http://lip.getlea.org/LIP-0001.html)):**
    * Full implementation of the extended Tag `10` field and its sub-types:
        * `SS=00`: Legacy 4-bit list indices (but see LIP-0004).
        * `SS=01`: Variable-length integers (Value `0`, ULEB128 for `uint64_t`, SLEB128 for `int64_t`).
        * `SS=10`: Common fixed-size data types (`int8` through `uint64`, `float`, `double`). (Little-Endian assumed as per spec).
        * `SS=11`: Boolean constants (`true`/`false`).

3.  **LIP-0002: Typed Crypto Schemes ([LIP-0002](http://lip.getlea.org/LIP-0002.html)):**
    * Utilization of type codes (`TT` bits) in Tag `00` and Tag `01` headers.
    * Support for multiple public key types/sizes (Ed25519, SLH-DSA variants).
    * Support for Ed25519 full signatures and 32-byte BLAKE3 hashes of PQC signatures within the Signature List.

4.  **LIP-0004: Decoupled List Index Reference ([LIP-0004.md](http://lip.getlea.org/LIP-0004.html)):**
    * Modifies the IxData Sub-Type `00` (`10xxxx00`) field, decoupling it from immediate list context.
    * Allows this index field to appear anywhere within the transaction data, including Command Data payloads.
    * Shifts the responsibility of associating the index with the correct target list (Public Key or Signature) and performing bounds checking to the higher-level application logic.

**(Note:** The scope is intentionally limited to these features to maintain minimality and facilitate auditing for the LEA Blockchain's requirements.)**

## Implementation Notes

### LEB128 Handling

* **Security Limit:** The decoder enforces a maximum read of 10 bytes for LEB128 numbers to mitigate resource exhaustion risks (as per LIP-0001).
* **Data Range:** Values are decoded into `uint64_t` / `int64_t`. Standard C integer wrap-around applies for valid encodings outside the 64-bit range.

## Intended Use

This `cte-core` repository is designated for use in the **LEA Blockchain**. It should primarily be updated with critical bug fixes relevant to the included feature set to maintain its stability and auditability. Development of new or experimental CTE features should occur elsewhere.