#pragma once

#include "enums.hpp"
#include <array>
/*
#define aux_lock        0x00000001
#define aux_rep         0x00000002
#define aux_repne       0x00000004
#define aux_use32       0x00000008  // segment type is 32-bits
#define aux_use64       0x00000010  // segment type is 64-bits
#define aux_large       0x00000020  // offset field is 32-bit (16-bit is not enough)
#define aux_short       0x00000040  // short (byte) displacement used
#define aux_sgpref      0x00000080  // a segment prefix byte is not used
#define aux_oppref      0x00000100  // operand size prefix byte is not used
#define aux_adpref      0x00000200  // address size prefix byte is not used
#define aux_basess      0x00000400  // SS based instruction
#define aux_natop       0x00000800  // operand size is not overridden by prefix
#define aux_natad       0x00001000  // addressing mode is not overridden by prefix
#define aux_fpemu       0x00002000  // FP emulator instruction
#define aux_vexpr       0x00004000  // VEX-encoded instruction
#define aux_bnd         0x00008000  // MPX-encoded instruction
#define aux_evex        0x00010000  // EVEX-encoded instruction
#define aux_xop         0x00020000  // XOP-encoded instruction
#define aux_xacquire    0x00040000  // HLE prefix hints
#define aux_xrelease    0x00080000  // HLE prefix hints
*/

namespace intel
{

    constexpr auto auxpref_flags = make_array(
        TO_ENUM(aux_lock, "Lock"),
         TO_ENUM(aux_rep, "Repeat"),
         TO_ENUM(aux_repne, "Repeat Not Equal"),
         TO_ENUM(aux_use32, "segment type is 32-bits"),
         TO_ENUM(aux_use64, "segment type is 64-bits"),
         TO_ENUM(aux_large, "offset field is 32-bit (16-bit is not enough)"),
         TO_ENUM(aux_short, "short (byte) displacement used"),
         TO_ENUM(aux_sgpref, "a segment prefix byte is not used"),
         TO_ENUM(aux_oppref, "operand size prefix byte is not used"),
         TO_ENUM(aux_adpref, "address size prefix byte is not used"),
         TO_ENUM(aux_basess, "SS based instruction"),
         TO_ENUM(aux_natop, "operand size is not overridden by prefix"),
         TO_ENUM(aux_natad, "addressing mode is not overridden by prefix"),
         TO_ENUM(aux_fpemu, "FP emulator instruction"),
         TO_ENUM(aux_vexpr, "VEX-encoded instruction"),
         TO_ENUM(aux_bnd, "MPX-encoded instruction"),
         TO_ENUM(aux_evex, "EVEX-encoded instruction"),
         TO_ENUM(aux_xop, "XOP-encoded instruction"),
         TO_ENUM(aux_xacquire, "HLE prefix hints"),
         TO_ENUM(aux_xrelease, "HLE prefix hints")
    );

    static AutoRegister _reg_auxpref_flags(auxpref_flags);

    constexpr auto registers = make_array(
            TO_ENUM(R_none, "No register"),
            TO_ENUM(R_ax, "AX"),
            TO_ENUM(R_cx, "CX"),
            TO_ENUM(R_dx, "DX"),
            TO_ENUM(R_bx, "BX"),
            TO_ENUM(R_sp, "SP"),
            TO_ENUM(R_bp, "BP"),
            TO_ENUM(R_si, "SI"),
            TO_ENUM(R_di, "DI"),
            TO_ENUM(R_r8, "R8"),
            TO_ENUM(R_r9, "R9"),
            TO_ENUM(R_r10, "R10"),
            TO_ENUM(R_r11, "R11"),
            TO_ENUM(R_r12, "R12"),
            TO_ENUM(R_r13, "R13"),
            TO_ENUM(R_r14, "R14"),
            TO_ENUM(R_r15, "R15"),

            TO_ENUM(R_al, "AL"),
            TO_ENUM(R_cl, "CL"),
            TO_ENUM(R_dl, "DL"),
            TO_ENUM(R_bl, "BL"),
            TO_ENUM(R_ah, "AH"),
            TO_ENUM(R_ch, "CH"),
            TO_ENUM(R_dh, "DH"),
            TO_ENUM(R_bh, "BH"),

            TO_ENUM(R_spl, "SPL"),
            TO_ENUM(R_bpl, "BPL"),
            TO_ENUM(R_sil, "SIL"),
            TO_ENUM(R_dil, "DIL"),

            TO_ENUM(R_ip, "IP"),

            TO_ENUM(R_es, "ES"), // 0
            TO_ENUM(R_cs, "CS"), // 1
            TO_ENUM(R_ss, "SS"), // 2
            TO_ENUM(R_ds, "DS"), // 3
            TO_ENUM(R_fs, "FS"),
            TO_ENUM(R_gs, "GS"),

            TO_ENUM(R_cf, "CF"), // main cc's
            TO_ENUM(R_zf, "ZF"),
            TO_ENUM(R_sf, "SF"),
            TO_ENUM(R_of, "OF"),

            TO_ENUM(R_pf, "PF"), // additional cc's
            TO_ENUM(R_af, "AF"),
            TO_ENUM(R_tf, "TF"),
            TO_ENUM(R_if, "IF"),
            TO_ENUM(R_df, "DF"),

            TO_ENUM(R_efl, "EFL"), // eflags

            // the following registers will be used in the disassembly
            // starting from ida v5.7

            TO_ENUM(R_st0, "ST0"), // floating point registers (not used in disassembly)
            TO_ENUM(R_st1, "ST1"),
            TO_ENUM(R_st2, "ST2"),
            TO_ENUM(R_st3, "ST3"),
            TO_ENUM(R_st4, "ST4"),
            TO_ENUM(R_st5, "ST5"),
            TO_ENUM(R_st6, "ST6"),
            TO_ENUM(R_st7, "ST7"),
            TO_ENUM(R_fpctrl, "FPCTRL"), // fpu control register
            TO_ENUM(R_fpstat, "FPSTAT"), // fpu status register
            TO_ENUM(R_fptags, "FPTAGS"), // fpu tags register

            TO_ENUM(R_mm0, "MM0"), // mmx registers
            TO_ENUM(R_mm1, "MM1"),
            TO_ENUM(R_mm2, "MM2"),
            TO_ENUM(R_mm3, "MM3"),
            TO_ENUM(R_mm4, "MM4"),
            TO_ENUM(R_mm5, "MM5"),
            TO_ENUM(R_mm6, "MM6"),
            TO_ENUM(R_mm7, "MM7"),

            TO_ENUM(R_xmm0, "XMM0"), // xmm registers
            TO_ENUM(R_xmm1, "XMM1"),
            TO_ENUM(R_xmm2, "XMM2"),
            TO_ENUM(R_xmm3, "XMM3"),
            TO_ENUM(R_xmm4, "XMM4"),
            TO_ENUM(R_xmm5, "XMM5"),
            TO_ENUM(R_xmm6, "XMM6"),
            TO_ENUM(R_xmm7, "XMM7"),
            TO_ENUM(R_xmm8, "XMM8"),
            TO_ENUM(R_xmm9, "XMM9"),
            TO_ENUM(R_xmm10, "XMM10"),
            TO_ENUM(R_xmm11, "XMM11"),
            TO_ENUM(R_xmm12, "XMM12"),
            TO_ENUM(R_xmm13, "XMM13"),
            TO_ENUM(R_xmm14, "XMM14"),
            TO_ENUM(R_xmm15, "XMM15"),
            TO_ENUM(R_mxcsr, "MXCSR"),

            TO_ENUM(R_ymm0, "YMM0"), // AVX 256-bit registers
            TO_ENUM(R_ymm1, "YMM1"),
            TO_ENUM(R_ymm2, "YMM2"),
            TO_ENUM(R_ymm3, "YMM3"),
            TO_ENUM(R_ymm4, "YMM4"),
            TO_ENUM(R_ymm5, "YMM5"),
            TO_ENUM(R_ymm6, "YMM6"),
            TO_ENUM(R_ymm7, "YMM7"),
            TO_ENUM(R_ymm8, "YMM8"),
            TO_ENUM(R_ymm9, "YMM9"),
            TO_ENUM(R_ymm10, "YMM10"),
            TO_ENUM(R_ymm11, "YMM11"),
            TO_ENUM(R_ymm12, "YMM12"),
            TO_ENUM(R_ymm13, "YMM13"),
            TO_ENUM(R_ymm14, "YMM14"),
            TO_ENUM(R_ymm15, "YMM15"),

            TO_ENUM(R_bnd0, "BND0"), // MPX registers
            TO_ENUM(R_bnd1, "BND1"),
            TO_ENUM(R_bnd2, "BND2"),
            TO_ENUM(R_bnd3, "BND3"),

            TO_ENUM(R_xmm16, "XMM16"), // AVX-512 extended XMM registers
            TO_ENUM(R_xmm17, "XMM17"),
            TO_ENUM(R_xmm18, "XMM18"),
            TO_ENUM(R_xmm19, "XMM19"),
            TO_ENUM(R_xmm20, "XMM20"),
            TO_ENUM(R_xmm21, "XMM21"),
            TO_ENUM(R_xmm22, "XMM22"),
            TO_ENUM(R_xmm23, "XMM23"),
            TO_ENUM(R_xmm24, "XMM24"),
            TO_ENUM(R_xmm25, "XMM25"),
            TO_ENUM(R_xmm26, "XMM26"),
            TO_ENUM(R_xmm27, "XMM27"),
            TO_ENUM(R_xmm28, "XMM28"),
            TO_ENUM(R_xmm29, "XMM29"),
            TO_ENUM(R_xmm30, "XMM30"),
                TO_ENUM(R_zmm31, "ZMM31"),
            TO_ENUM(R_ymm17, "YMM17"),
            TO_ENUM(R_ymm18, "YMM18"),
            TO_ENUM(R_ymm19, "YMM19"),
            TO_ENUM(R_ymm20, "YMM20"),
            TO_ENUM(R_ymm21, "YMM21"),
            TO_ENUM(R_ymm22, "YMM22"),
            TO_ENUM(R_ymm23, "YMM23"),
            TO_ENUM(R_ymm24, "YMM24"),
            TO_ENUM(R_ymm25, "YMM25"),
            TO_ENUM(R_ymm26, "YMM26"),
            TO_ENUM(R_ymm27, "YMM27"),
            TO_ENUM(R_ymm28, "YMM28"),
            TO_ENUM(R_ymm29, "YMM29"),
            TO_ENUM(R_ymm30, "YMM30"),
            TO_ENUM(R_ymm31, "YMM31"),

            TO_ENUM(R_zmm0, "ZMM0"), // AVX-512 ZMM registers
            TO_ENUM(R_zmm1, "ZMM1"),
            TO_ENUM(R_zmm2, "ZMM2"),
            TO_ENUM(R_zmm3, "ZMM3"),
            TO_ENUM(R_zmm4, "ZMM4"),
            TO_ENUM(R_zmm5, "ZMM5"),
            TO_ENUM(R_zmm6, "ZMM6"),
            TO_ENUM(R_zmm7, "ZMM7"),
            TO_ENUM(R_zmm8, "ZMM8"),
            TO_ENUM(R_zmm9, "ZMM9"),
            TO_ENUM(R_zmm10, "ZMM10"),
            TO_ENUM(R_zmm11, "ZMM11"),
            TO_ENUM(R_zmm12, "ZMM12"),
            TO_ENUM(R_zmm13, "ZMM13"),
            TO_ENUM(R_zmm14, "ZMM14"),
            TO_ENUM(R_zmm15, "ZMM15"),
            TO_ENUM(R_zmm16, "ZMM16"),
            TO_ENUM(R_zmm17, "ZMM17"),
            TO_ENUM(R_zmm18, "ZMM18"),
            TO_ENUM(R_zmm19, "ZMM19"),
            TO_ENUM(R_zmm20, "ZMM20"),
            TO_ENUM(R_zmm21, "ZMM21"),
            TO_ENUM(R_zmm22, "ZMM22"),
            TO_ENUM(R_zmm23, "ZMM23"),
            TO_ENUM(R_zmm24, "ZMM24"),
            TO_ENUM(R_zmm25, "ZMM25"),
            TO_ENUM(R_zmm26, "ZMM26"),
            TO_ENUM(R_zmm27, "ZMM27"),
            TO_ENUM(R_zmm28, "ZMM28"),
            TO_ENUM(R_zmm29, "ZMM29"),
            TO_ENUM(R_zmm30, "ZMM30"),
            TO_ENUM(R_zmm31, "ZMM31"),

            TO_ENUM(R_k0, "K0"), // AVX-512 opmask registers
            TO_ENUM(R_k1, "K1"),
            TO_ENUM(R_k2, "K2"),
            TO_ENUM(R_k3, "K3"),
            TO_ENUM(R_k4, "K4"),
            TO_ENUM(R_k5, "K5"),
            TO_ENUM(R_k6, "K6"),
            TO_ENUM(R_k7, "K7"),

                TO_ENUM(R_last, "LAST")
            );
    static AutoRegister _reg_registers(registers);
}