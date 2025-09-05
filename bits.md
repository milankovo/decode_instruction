# IDA Flags Overview

This document provides an overview of all flag bits defined in `bytes.hpp`, grouped by their respective `MS_xxx` masks. Each table shows the flag name, its hex value, and its bit representation.

---
         DDDD 2222 1111 AAAA AAAA ACCV BBBB BBBB

with operand flags:
  UUUU UUUU 8888 7777 6666 5555 4444 3333 DDDD 2222 1111 AAAA AAAA ACCV BBBB BBBB


0000000000000000000000000000000000000000111100000000000000000000
0000000000000000000000000000000000002222000000000000000000000000
0000000000000000000000000000333300000000000000000000000000000000
0000000000000000000000004444000000000000000000000000000000000000
0000000000000000000055550000000000000000000000000000000000000000
0000000000000000666600000000000000000000000000000000000000000000
0000000000007777000000000000000000000000000000000000000000000000
0000000088880000000000000000000000000000000000000000000000000000

B ... byte value
V ... value defined
C ... Byte state
A ... Common State Info
1 ... operand 1
2 ... operand 2
3 ... operand 3
4 ... operand 4
5 ... operand 5
6 ... operand 6
7 ... operand 7
8 ... operand 8
U ... unused


## 1. Byte Value and Initialization (`MS_VAL`)

| Flag Name | Hex Value   | Bit Representation         | Description                |
|-----------|-------------|---------------------------|----------------------------|
| MS_VAL    | 0x000000FF  | 0000 0000 0000 0000 0000 0000 1111 1111 | Mask for byte value        |
| FF_IVL    | 0x00000100  | 0000 0000 0000 0000 0000 0001 0000 0000 | Byte has value             |

---

## 2. Byte State (`MS_CLS`)

| Flag Name | Hex Value   | Bit Representation         | Description                |
|-----------|-------------|---------------------------|----------------------------|
| MS_CLS    | 0x00000600  | 0000 0000 0000 0000 0000 0110 0000 0000 | Mask for typing            |
| FF_CODE   | 0x00000600  | 0000 0000 0000 0000 0000 0110 0000 0000 | Code?                      |
| FF_DATA   | 0x00000400  | 0000 0000 0000 0000 0000 0100 0000 0000 | Data?                      |
| FF_TAIL   | 0x00000200  | 0000 0000 0000 0000 0000 0010 0000 0000 | Tail?                      |
| FF_UNK    | 0x00000000  | 0000 0000 0000 0000 0000 0000 0000 0000 | Unknown?                   |

---

## 3. Common State Info (`MS_COMM`)

| Flag Name | Hex Value   | Bit Representation         | Description                |
|-----------|-------------|---------------------------|----------------------------|
| MS_COMM   | 0x000FF800  | 0000 0000 0000 1111 1111 1000 0000 0000 | Mask of common bits        |
| FF_COMM   | 0x00000800  | 0000 0000 0000 0000 0000 1000 0000 0000 | Has comment?               |
| FF_REF    | 0x00001000  | 0000 0000 0000 0000 0001 0000 0000 0000 | Has references             |
| FF_LINE   | 0x00002000  | 0000 0000 0000 0000 0010 0000 0000 0000 | Has next/prev lines        |
| FF_NAME   | 0x00004000  | 0000 0000 0000 0000 0100 0000 0000 0000 | Has name?                  |
| FF_LABL   | 0x00008000  | 0000 0000 0000 0000 1000 0000 0000 0000 | Has dummy name?            |
| FF_FLOW   | 0x00010000  | 0000 0000 0000 0001 0000 0000 0000 0000 | Exec flow from prev insn   |
| FF_SIGN   | 0x00020000  | 0000 0000 0000 0010 0000 0000 0000 0000 | Inverted sign of operands  |
| FF_BNOT   | 0x00040000  | 0000 0000 0000 0100 0000 0000 0000 0000 | Bitwise negation of ops    |
| FF_UNUSED | 0x00080000  | 0000 0000 0000 1000 0000 0000 0000 0000 | Unused bit                 |

---

## 4. Operand Type (`MS_N_TYPE`)

| Flag Name   | Hex Value | Bit Representation | Description                |
|-------------|-----------|-------------------|----------------------------|
| MS_N_TYPE   | 0xF       | 1111              | Mask for nth arg (nibble)  |
| FF_N_VOID   | 0x0       | 0000              | Void (unknown)?            |
| FF_N_NUMH   | 0x1       | 0001              | Hexadecimal number?        |
| FF_N_NUMD   | 0x2       | 0010              | Decimal number?            |
| FF_N_CHAR   | 0x3       | 0011              | Char ('x')?                |
| FF_N_SEG    | 0x4       | 0100              | Segment?                   |
| FF_N_OFF    | 0x5       | 0101              | Offset?                    |
| FF_N_NUMB   | 0x6       | 0110              | Binary number?             |
| FF_N_NUMO   | 0x7       | 0111              | Octal number?              |
| FF_N_ENUM   | 0x8       | 1000              | Enumeration?               |
| FF_N_FOP    | 0x9       | 1001              | Forced operand?            |
| FF_N_STRO   | 0xA       | 1010              | Struct offset?             |
| FF_N_STK    | 0xB       | 1011              | Stack variable?            |
| FF_N_FLT    | 0xC       | 1100              | Floating point number?     |
| FF_N_CUST   | 0xD       | 1101              | Custom representation?     |

---

## 5. Data Type (`DT_TYPE`)

| Flag Name   | Hex Value   | Bit Representation         | Description                |
|-------------|-------------|---------------------------|----------------------------|
| DT_TYPE     | 0xF0000000  | 1111 0000 0000 0000 0000 0000 0000 0000 | Mask for DATA typing        |
| FF_BYTE     | 0x00000000  | 0000 0000 0000 0000 0000 0000 0000 0000 | Byte                        |
| FF_WORD     | 0x10000000  | 0001 0000 0000 0000 0000 0000 0000 0000 | Word                        |
| FF_DWORD    | 0x20000000  | 0010 0000 0000 0000 0000 0000 0000 0000 | Double word                 |
| FF_QWORD    | 0x30000000  | 0011 0000 0000 0000 0000 0000 0000 0000 | Quad word                   |
| FF_TBYTE    | 0x40000000  | 0100 0000 0000 0000 0000 0000 0000 0000 | Tbyte                       |
| FF_STRLIT   | 0x50000000  | 0101 0000 0000 0000 0000 0000 0000 0000 | String literal              |
| FF_STRUCT   | 0x60000000  | 0110 0000 0000 0000 0000 0000 0000 0000 | Struct variable             |
| FF_OWORD    | 0x70000000  | 0111 0000 0000 0000 0000 0000 0000 0000 | Octaword/xmm word           |
| FF_FLOAT    | 0x80000000  | 1000 0000 0000 0000 0000 0000 0000 0000 | Float                       |
| FF_DOUBLE   | 0x90000000  | 1001 0000 0000 0000 0000 0000 0000 0000 | Double                      |
| FF_PACKREAL | 0xA0000000  | 1010 0000 0000 0000 0000 0000 0000 0000 | Packed decimal real         |
| FF_ALIGN    | 0xB0000000  | 1011 0000 0000 0000 0000 0000 0000 0000 | Alignment directive         |
| FF_CUSTOM   | 0xD0000000  | 1101 0000 0000 0000 0000 0000 0000 0000 | Custom data type            |
| FF_YWORD    | 0xE0000000  | 1110 0000 0000 0000 0000 0000 0000 0000 | Ymm word                    |
| FF_ZWORD    | 0xF0000000  | 1111 0000 0000 0000 0000 0000 0000 0000 | Zmm word                    |

---

## 6. Code Bits (`MS_CODE`)

| Flag Name | Hex Value   | Bit Representation         | Description                |
|-----------|-------------|---------------------------|----------------------------|
| MS_CODE   | 0xF0000000  | 1111 0000 0000 0000 0000 0000 0000 0000 | Mask for code bits          |
| FF_FUNC   | 0x10000000  | 0001 0000 0000 0000 0000 0000 0000 0000 | Function start?             |
| FF_IMMD   | 0x40000000  | 0100 0000 0000 0000 0000 0000 0000 0000 | Has Immediate value?        |
| FF_JUMP   | 0x80000000  | 1000 0000 0000 0000 0000 0000 0000 0000 | Has jump table/switch_info? |

---

**Notes:**

- Masks like `MS_VAL`, `MS_CLS`, `MS_COMM`, `DT_TYPE`, `MS_CODE` are used to extract or set specific groups of bits.
- Operand type flags (`FF_N_*`) are stored in nibbles at specific bit positions, one per operand.
- Data type and code bits overlap in the high nibble (bits 28-31).
- For more details, refer to the comments and inline functions in `bytes.hpp



final representation (mockup):
UUUU 8888 7777 6666 5555 4444 3333 DDDD 2222 1111 AAAA AAAA ACCV BBBB BBBB
     :    :    :    :    :    :    :    :    :    :::        : : :.. byte value
     :    :    :    :    :    :    :    :    :    :::        : :.. Byte has value
     :    :    :    :    :    :    :    :    :    :::        :.. one of MS_CLS
     :    :    :    :    :    :    :    :    :    :::.. FF_SIGN (if present)
     :    :    :    :    :    :    :    :    :    ::.. FF_BNOT (if present)
     :    :    :    :    :    :    :    :    :    :.. FF_UNUSED (if present)
     :    :    :    :    :    :    :    :    :.. op1 flags
     :    :    :    :    :    :    :    :.. op2 flags
     :    :    :    :    :    :    :.. one of DT_TYPE / MS_CODE flags here
     :    :    :    :    :    :.. op3 flags
     :    :    :    :    :.. op4 flags
     :    :    :    :.. op5 flags
     :    :    :.. op6 flags
     :    :.. op7 flags
     :.. op8 flags