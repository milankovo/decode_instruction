import re
from dataclasses import dataclass
from collections import defaultdict
from pathlib import Path

# Path to the input file
input_file = Path("/Users/milanek/Documents/idasdk92/include/allins.hpp")
out_dir = Path("./architectures")
out_dir.mkdir(exist_ok=True, parents=True)
# Output structures
flags_array = defaultdict(list)

def make_pattern(arch):
    # Regular expression to match NN_.* and ARM_.* constants with or without comments, including assignments
    return re.compile(r"\b(" + arch + r"_[a-zA-Z0-9_]+)(?:=([a-zA-Z0-9_]+))?\b\s*,?\s*(?://\s*(.*))?")

@dataclass
class ArchitecturePattern:
    name: str
    pattern: re.Pattern

architectures = [
    ArchitecturePattern("PLFM_386", make_pattern("NN")),
    ArchitecturePattern("PLFM_Z80", make_pattern("I5")),
    ArchitecturePattern("PLFM_I860", make_pattern("I860")),
    ArchitecturePattern("PLFM_8051", make_pattern("I51")),
    ArchitecturePattern("PLFM_TMS", make_pattern("TMS")),
    ArchitecturePattern("PLFM_6502", make_pattern("M65")),
    ArchitecturePattern("PLFM_PDP", make_pattern("pdp")),
    ArchitecturePattern("PLFM_68K", make_pattern("mc")),
    ArchitecturePattern("PLFM_JAVA", make_pattern("j")),
    ArchitecturePattern("PLFM_6800", make_pattern("mc8")),
    ArchitecturePattern("PLFM_ST7", make_pattern("ST7")),
    ArchitecturePattern("PLFM_MC6812", make_pattern("MC12")),
    ArchitecturePattern("PLFM_MIPS", make_pattern("MIPS")),
    ArchitecturePattern("PLFM_ARM", make_pattern("ARM")),
    ArchitecturePattern("PLFM_TMSC6", make_pattern("TMS6")),
    ArchitecturePattern("PLFM_PPC", make_pattern("PPC")),
    ArchitecturePattern("PLFM_80196", make_pattern("I196")),
    ArchitecturePattern("PLFM_Z8", make_pattern("Z8")),
    ArchitecturePattern("PLFM_SH", make_pattern("SH4")),
    ArchitecturePattern("PLFM_NET", make_pattern("NET")),
    ArchitecturePattern("PLFM_AVR", make_pattern("AVR")),
    ArchitecturePattern("PLFM_H8", make_pattern("H8")),
    ArchitecturePattern("PLFM_PIC", make_pattern("PIC")),
    ArchitecturePattern("PLFM_SPARC", make_pattern("SPARC")),
    ArchitecturePattern("PLFM_ALPHA", make_pattern("ALPHA")),
    ArchitecturePattern("PLFM_HPPA", make_pattern("HPPA")),
    ArchitecturePattern("PLFM_H8500", make_pattern("H8500")),
    ArchitecturePattern("PLFM_TRICORE", make_pattern("TRICORE")),
    ArchitecturePattern("PLFM_DSP56K", make_pattern("DSP56")),
    ArchitecturePattern("PLFM_C166", make_pattern("C166")),
    ArchitecturePattern("PLFM_ST20", make_pattern("ST20")),
    ArchitecturePattern("PLFM_IA64", make_pattern("IA64")),
    ArchitecturePattern("PLFM_I960", make_pattern("I960")),
    ArchitecturePattern("PLFM_F2MC", make_pattern("F2MC")),
    ArchitecturePattern("PLFM_TMS320C54", make_pattern("TMS320C54")),
    ArchitecturePattern("PLFM_TMS320C55", make_pattern("TMS320C55")),
    ArchitecturePattern("PLFM_TRIMEDIA", make_pattern("TRIMEDIA")),
    ArchitecturePattern("PLFM_M32R", make_pattern("m32r")),
    ArchitecturePattern("PLFM_NEC_78K0", make_pattern("NEC_78K_0")),
    ArchitecturePattern("PLFM_NEC_78K0S", make_pattern("NEC_78K_0S")),
    ArchitecturePattern("PLFM_M740", make_pattern("m740")),
    ArchitecturePattern("PLFM_M7700", make_pattern("m7700")),
    ArchitecturePattern("PLFM_ST9", make_pattern("st9")),
    ArchitecturePattern("PLFM_FR", make_pattern("fr")),
    ArchitecturePattern("PLFM_MC6816", make_pattern("MC6816")),
    ArchitecturePattern("PLFM_M7900", make_pattern("m7900")),
    ArchitecturePattern("PLFM_TMS320C3", make_pattern("TMS320C3X")),
    ArchitecturePattern("PLFM_KR1878", make_pattern("KR1878")),
    ArchitecturePattern("PLFM_AD218X", make_pattern("AD218X")),
    ArchitecturePattern("PLFM_OAKDSP", make_pattern("OAK_Dsp")),
    ArchitecturePattern("PLFM_TLCS900", make_pattern("T900")),
    ArchitecturePattern("PLFM_C39", make_pattern("C39")),
    ArchitecturePattern("PLFM_CR16", make_pattern("CR16")),
    ArchitecturePattern("PLFM_MN102L00", make_pattern("mn102")),
    # N/A architectures - commented out as they don't have instruction patterns
    # ArchitecturePattern("PLFM_TMS320C1X", make_pattern("N/A")),
    ArchitecturePattern("PLFM_NEC_V850X", make_pattern("NEC850")),
    # ArchitecturePattern("PLFM_SCR_ADPT", make_pattern("N/A")),
    # ArchitecturePattern("PLFM_EBC", make_pattern("N/A")),
    # ArchitecturePattern("PLFM_MSP430", make_pattern("N/A")),
    # ArchitecturePattern("PLFM_SPU", make_pattern("N/A")),
    ArchitecturePattern("PLFM_DALVIK", make_pattern("DALVIK")),
    ArchitecturePattern("PLFM_65C816", make_pattern("M65816")),
    ArchitecturePattern("PLFM_M16C", make_pattern("M16C")),
    ArchitecturePattern("PLFM_ARC", make_pattern("ARC")),
    ArchitecturePattern("PLFM_UNSP", make_pattern("UNSP")),
    ArchitecturePattern("PLFM_TMS320C28", make_pattern("TMS28")),
    ArchitecturePattern("PLFM_DSP96K", make_pattern("DSP96")),
    # N/A architectures - commented out as they don't have instruction patterns
    # ArchitecturePattern("PLFM_SPC700", make_pattern("N/A")),
    # ArchitecturePattern("PLFM_AD2106X", make_pattern("N/A")),
    ArchitecturePattern("PLFM_PIC16", make_pattern("PIC16")),
    ArchitecturePattern("PLFM_S390", make_pattern("s39")),
    ArchitecturePattern("PLFM_XTENSA", make_pattern("XTENSA")),
    ArchitecturePattern("PLFM_RISCV", make_pattern("RISCV")),
    ArchitecturePattern("PLFM_RL78", make_pattern("RL78")),
    ArchitecturePattern("PLFM_RX", make_pattern("RX")),
    # N/A architectures - commented out as they don't have instruction patterns  
    # ArchitecturePattern("PLFM_WASM", make_pattern("N/A"))
]

for arch in architectures:
    # Read the input file and extract matches
    skip = False
    with input_file.open("r") as file:
        for line in file:
            line = line.strip()
            if line.startswith("//") or not line:
                continue
            if line.startswith("*/"):
                skip = False
                continue
            if line.startswith("/*"):
                skip = True
                continue
            if skip:
                continue

            match = arch.pattern.search(line)
            if not match:
                continue
            constant, alias, comment = match.groups()
            if alias:
                comment = (comment or "") + f" (same as {alias})"
            if not comment:
                comment = f"Undocumented instruction {constant}"
            if comment:
                comment = comment.replace('"', r'\"')
            flags_array[arch.name].append(f"\tTO_ENUM({constant}, \"{comment}\")")

for arch in architectures:
    # Write the extracted data to output files
    output_file: Path = out_dir / f"instructions_{arch.name}.hpp"

    with output_file.open("w") as flags_file:
        flags_file.write(f"auto instructions_{arch.name} = flags_vector_t{{\n")
        flags_file.write(",\n".join(flags_array[arch.name]))
        flags_file.write("\n};\n")

print("Extraction complete. Check the output files for results.")
