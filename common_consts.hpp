#pragma once
#include <array>
#include <bytes.hpp>
#include "enums.hpp"

/*

#define OF_NO_BASE_DISP 0x80  ///< base displacement doesn't exist.
                              ///< meaningful only for ::o_displ type.
                              ///< if set, base displacement (op_t::addr)
                              ///< doesn't exist.
#define OF_OUTER_DISP   0x40  ///< outer displacement exists.                              
                              ///< meaningful only for ::o_displ type.
                              ///< if set, outer displacement (op_t::value) exists.
#define PACK_FORM_DEF   0x20  ///< packed factor defined.
                              ///< (!::o_reg + #dt_packreal)
#define OF_NUMBER       0x10  ///< the operand can be converted to a number only
#define OF_SHOW         0x08  ///< should the operand be displayed?
 */

auto operand_flags = std::to_array({
    TO_ENUM(OF_NO_BASE_DISP, "base displacement doesn't exist"),         // OF_NO_BASE_DISP
    TO_ENUM(OF_OUTER_DISP, "outer displacement exists"),                 // OF_OUTER_DISP
    TO_ENUM(PACK_FORM_DEF, "packed factor defined"),                     // PACK_FORM_DEF
    TO_ENUM(OF_NUMBER, "the operand can be converted to a number only"), // OF_NUMBER
    TO_ENUM(OF_SHOW, "should the operand be displayed?")                 // OF_SHOW
});

static AutoRegister _reg_operand_flags(operand_flags);

/*
#define dt_byte         0     ///< 8 bit integer
#define dt_word         1     ///< 16 bit integer
#define dt_dword        2     ///< 32 bit integer
#define dt_float        3     ///< 4 byte floating point
#define dt_double       4     ///< 8 byte floating point
#define dt_tbyte        5     ///< variable size (\ph{tbyte_size}) floating point
#define dt_packreal     6     ///< packed real format for mc68040
// ...to here the order should not be changed, see mc68000
#define dt_qword        7     ///< 64 bit integer
#define dt_byte16       8     ///< 128 bit integer
#define dt_code         9     ///< ptr to code
#define dt_void         10    ///< none
#define dt_fword        11    ///< 48 bit
#define dt_bitfild      12    ///< bit field (mc680x0)
#define dt_string       13    ///< pointer to asciiz string
#define dt_unicode      14    ///< pointer to unicode string
#define dt_ldbl         15    ///< long double (which may be different from tbyte)
#define dt_byte32       16    ///< 256 bit integer
#define dt_byte64       17    ///< 512 bit integer
#define dt_half         18    ///< 2-byte floating point
*/

auto dtype_flags = std::to_array({
    TO_ENUM(dt_byte, "8 bit integer"),     // dt_byte
    TO_ENUM(dt_word, "16 bit integer"),     // dt_word
    TO_ENUM(dt_dword, "32 bit integer"),    // dt_dword
    TO_ENUM(dt_float, "4 byte floating point"),    // dt_float
    TO_ENUM(dt_double, "8 byte floating point"),   // dt_double
    TO_ENUM(dt_tbyte, "variable size floating point"),    // dt_tbyte
    TO_ENUM(dt_packreal, "packed real format for mc68040"), // dt_packreal
    TO_ENUM(dt_qword, "64 bit integer"),    // dt_qword
    TO_ENUM(dt_byte16, "128 bit integer"),   // dt_byte16
    TO_ENUM(dt_code, "ptr to code"),     // dt_code
    TO_ENUM(dt_void, "none"),     // dt_void
    TO_ENUM(dt_fword, "48 bit"),    // dt_fword
    TO_ENUM(dt_bitfild, "bit field (mc680x0)"),  // dt_bitfild
    TO_ENUM(dt_string, "pointer to asciiz string"),   // dt_string
    TO_ENUM(dt_unicode, "pointer to unicode string"),  // dt_unicode
    TO_ENUM(dt_ldbl, "long double (which may be different from tbyte)"),     // dt_ldbl
    TO_ENUM(dt_byte32, "256 bit integer"),   // dt_byte32
    TO_ENUM(dt_byte64, "512 bit integer"),   // dt_byte64
    TO_ENUM(dt_half, "2-byte floating point"),     // dt_half
});

static AutoRegister _reg_dtype_flags(dtype_flags);

/*
const optype_t
  o_void     =  0, ///< No Operand.
  o_reg      =  1, ///< General Register (al,ax,es,ds...).
  o_mem      =  2, ///< A direct memory reference to a data item.
                   ///< Use this operand type when the address can be
                   ///< calculated statically.
  o_phrase   =  3, ///< An indirect memory reference that uses a register: [reg]
                   ///< There can be several registers but no displacement.
  o_displ    =  4, ///< An indirect memory reference that uses a register and
                   ///< has an immediate constant added to it: [reg+N]
                   ///< There can be several registers.
  o_imm      =  5, ///< An immediate Value (constant).
  o_far      =  6, ///< An immediate far code reference (inter-segment)
  o_near     =  7, ///< An immediate near code reference (intra-segment)
  o_idpspec0 =  8, ///< processor specific type.
  o_idpspec1 =  9, ///< processor specific type.
  o_idpspec2 = 10, ///< processor specific type.
  o_idpspec3 = 11, ///< processor specific type.
  o_idpspec4 = 12, ///< processor specific type.
  o_idpspec5 = 13; ///< processor specific type.
                   ///< (there can be more processor specific types)
///@}
*/

/*
o_void     = ida_ua.o_void      # No Operand                           ----------
o_reg      = ida_ua.o_reg       # General Register (al,ax,es,ds...)    reg
o_mem      = ida_ua.o_mem       # Direct Memory Reference  (DATA)      addr
o_phrase   = ida_ua.o_phrase    # Memory Ref [Base Reg + Index Reg]    phrase
o_displ    = ida_ua.o_displ     # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
o_imm      = ida_ua.o_imm       # Immediate Value                      value
o_far      = ida_ua.o_far       # Immediate Far Address  (CODE)        addr
o_near     = ida_ua.o_near      # Immediate Near Address (CODE)        addr
o_idpspec0 = ida_ua.o_idpspec0  # Processor specific type
o_idpspec1 = ida_ua.o_idpspec1  # Processor specific type
o_idpspec2 = ida_ua.o_idpspec2  # Processor specific type
o_idpspec3 = ida_ua.o_idpspec3  # Processor specific type
o_idpspec4 = ida_ua.o_idpspec4  # Processor specific type
o_idpspec5 = ida_ua.o_idpspec5  # Processor specific type
                                # There can be more processor specific types

# x86
o_trreg  =       ida_ua.o_idpspec0      # trace register
o_dbreg  =       ida_ua.o_idpspec1      # debug register
o_crreg  =       ida_ua.o_idpspec2      # control register
o_fpreg  =       ida_ua.o_idpspec3      # floating point register
o_mmxreg  =      ida_ua.o_idpspec4      # mmx register
o_xmmreg  =      ida_ua.o_idpspec5      # xmm register

# arm
o_reglist  =     ida_ua.o_idpspec1      # Register list (for LDM/STM)
o_creglist  =    ida_ua.o_idpspec2      # Coprocessor register list (for CDP)
o_creg  =        ida_ua.o_idpspec3      # Coprocessor register (for LDC/STC)
o_fpreglist  =   ida_ua.o_idpspec4      # Floating point register list
o_text  =        ida_ua.o_idpspec5      # Arbitrary text stored in the operand
o_cond  =        (ida_ua.o_idpspec5+1)  # ARM condition as an operand

# ppc
o_spr  =         ida_ua.o_idpspec0      # Special purpose register
o_twofpr  =      ida_ua.o_idpspec1      # Two FPRs
o_shmbme  =      ida_ua.o_idpspec2      # SH & MB & ME
o_crf  =         ida_ua.o_idpspec3      # crfield      x.reg
o_crb  =         ida_ua.o_idpspec4      # crbit        x.reg
o_dcr  =         ida_ua.o_idpspec5      # Device control register
*/

// TODO: figure out how to specialize it for other processor types
constexpr auto optype_flags = std::to_array({
    TO_ENUM(o_void, "No Operand"),
    TO_ENUM(o_reg, "General Register (al,ax,es,ds...)"),
    TO_ENUM(o_mem, "Direct Memory Reference"),
    TO_ENUM(o_phrase, "Indirect Memory Reference using Register"),
    TO_ENUM(o_displ, "Indirect Memory Reference with Displacement"),
    TO_ENUM(o_imm, "Immediate Value"),
    TO_ENUM(o_far, "Immediate Far Code Reference"),
    TO_ENUM(o_near, "Immediate Near Code Reference"),
    TO_ENUM(o_idpspec0, "Processor Specific Type 0"),
    TO_ENUM(o_idpspec1, "Processor Specific Type 1"),
    TO_ENUM(o_idpspec2, "Processor Specific Type 2"),
    TO_ENUM(o_idpspec3, "Processor Specific Type 3"),
    TO_ENUM(o_idpspec4, "Processor Specific Type 4"),
    TO_ENUM(o_idpspec5, "Processor Specific Type 5"),
    {o_idpspec5+1, "o_cond", "ARM condition as an operand"},
/*
    #define o_text        o_idpspec5           // Arbitrary text stored in the operand
                                           // structure starting at the 'value' field
                                           // up to 16 bytes (with terminating zero)
    #define o_cond        o_idpspec5+1         // ARM condition as an operand
*/                                         // condition is stored in 'value' field
});

static AutoRegister _reg_optype_flags(optype_flags);


/*
#define INSN_MACRO  0x01        ///< macro instruction
#define INSN_MODMAC 0x02        ///< may modify the database to make room for the macro insn
#define INSN_64BIT  0x04        ///< belongs to 64bit segment?
*/

auto insn_flags = std::to_array({
    TO_ENUM(INSN_MACRO, "macro instruction"),
    TO_ENUM(INSN_MODMAC, "may modify the database to make room for the macro insn"),
    TO_ENUM(INSN_64BIT, "belongs to 64bit segment?"),
});

static AutoRegister _reg_insn_flags(insn_flags);

auto ff_flags = std::to_array({
    TO_ENUM(FF_CODE, "Code"),
    TO_ENUM(FF_DATA, "Data"),
    TO_ENUM(FF_TAIL, "Tail"),
    TO_ENUM(FF_UNK, "Unknown"),
    TO_ENUM(MS_CLS, "Mask for typing"),

    TO_ENUM(FF_COMM, "has comment?"),
    TO_ENUM(FF_REF, "has references"),
    TO_ENUM(FF_LINE, "has next or prev lines?"),
    TO_ENUM(FF_NAME, "has name?"),
    TO_ENUM(FF_LABL, "has dummy name?"),
    TO_ENUM(FF_FLOW, "Exec flow from prev instruction"),
    TO_ENUM(FF_SIGN, "Inverted sign of operands"),
    TO_ENUM(FF_BNOT, "Bitwise negation of operands"),
    TO_ENUM(FF_UNUSED, "unused bit"),
    {0x40000000, "FF_IMMD", "Has Immediate value?"},
    {0x80000000, "FF_JUMP", "Has jump table or switch_info?"},
    {0x10000000, "FF_FUNC", "function start?"},
    {0x00000100, "FF_IVL", "Byte has a value"},
    {0x00000600, "MS_CLS", "Mask for typing"},
    // MS_VAL
    {0x000000FF, "MS_VAL", "Mask for value"},
});

static AutoRegister _reg_ff_flags(ff_flags);

auto ff_optype_flags = std::to_array({
    TO_ENUM(FF_N_VOID, "Void (unknown)"),
    TO_ENUM(FF_N_NUMH, "Hexadecimal number"),
    TO_ENUM(FF_N_NUMD, "Decimal number"),
    TO_ENUM(FF_N_CHAR, "Char ('x')"),
    TO_ENUM(FF_N_SEG, "Segment"),
    TO_ENUM(FF_N_OFF, "Offset"),
    TO_ENUM(FF_N_NUMB, "Binary number"),
    TO_ENUM(FF_N_NUMO, "Octal number"),
    TO_ENUM(FF_N_ENUM, "Enumeration"),
    TO_ENUM(FF_N_FOP, "Forced operand"),
    TO_ENUM(FF_N_STRO, "Struct offset"),
    TO_ENUM(FF_N_STK, "Stack variable"),
    TO_ENUM(FF_N_FLT, "Floating point number"),
    TO_ENUM(FF_N_CUST, "Custom representation"),
});

static AutoRegister _reg_ff_optype_flags(ff_optype_flags);

auto ff_dtype_flags = std::to_array({
    TO_ENUM(FF_BYTE, "byte"),
    TO_ENUM(FF_WORD, "word"),
    TO_ENUM(FF_DWORD, "double word"),
    TO_ENUM(FF_QWORD, "quadro word"),
    TO_ENUM(FF_TBYTE, "tbyte"),
    TO_ENUM(FF_STRLIT, "string literal"),
    TO_ENUM(FF_STRUCT, "struct variable"),
    TO_ENUM(FF_OWORD, "octaword/xmm word (16 bytes/128 bits)"),
    TO_ENUM(FF_FLOAT, "float"),
    TO_ENUM(FF_DOUBLE, "double"),
    TO_ENUM(FF_PACKREAL, "packed decimal real"),
    TO_ENUM(FF_ALIGN, "alignment directive"),
    TO_ENUM(FF_CUSTOM, "custom data type"),
    TO_ENUM(FF_YWORD, "ymm word (32 bytes/256 bits)"),
    TO_ENUM(FF_ZWORD, "zmm word (64 bytes/512 bits)"),
});

static AutoRegister _reg_ff_dtype_flags(ff_dtype_flags);