#pragma once
#include <pro.h>
#include <allins.hpp>
#include "enums.hpp"

#include "architectures/instructions_PLFM_386.hpp"
#include "architectures/instructions_PLFM_ARM.hpp"
#include "architectures/instructions_PLFM_MIPS.hpp"
#include "architectures/instructions_PLFM_RISCV.hpp"
#include "architectures/instructions_PLFM_ARC.hpp"
#include "architectures/instructions_PLFM_PPC.hpp"

#include <map>
#include <string>

const std::map<int, const flags_vector_t &> instructions_map = {
    {PLFM_386, instructions_PLFM_386},
    {PLFM_ARM, instructions_PLFM_ARM},
    {PLFM_MIPS, instructions_PLFM_MIPS},
    {PLFM_RISCV, instructions_PLFM_RISCV},
    {PLFM_ARC, instructions_PLFM_ARC},
    {PLFM_PPC, instructions_PLFM_PPC},
};

/*
//-------------------------------------------------------------------------
/// Custom instruction codes defined by processor extension plugins
/// must be greater than or equal to this
#define CUSTOM_INSN_ITYPE 0x8000
*/

qstring get_instruction_name(int32 arch, uint16 itype)
{
    if (itype >= CUSTOM_INSN_ITYPE)
    {
        return qstring().sprnt("CUSTOM_INSN_ITYPE+%#x", itype - CUSTOM_INSN_ITYPE);
    }

    auto it = instructions_map.find(arch);
    if (it != instructions_map.end())
    {
        const flags_vector_t &flags = it->second;
        auto flag_it = std::lower_bound(flags.begin(), flags.end(), itype, [](const auto &flag, int value)
                                        { return flag.value < value; });

        if (flag_it != flags.end())
        {
            qstring name = flag_it->name;
            name.cat_sprnt(COLSTR(" // %#x", SCOLOR_AUTOCMT), itype);
            return name;
        }
    }
    return qstring().sprnt("Unknown instruction %#x for architecture %d", itype, arch);
}