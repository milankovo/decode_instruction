// decode_instruction.cpp
// Custom plugin to decode and display instruction details
#define BYTES_SOURCE 1
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <bitset>
#include <intel.hpp>

#define COMMENT(x) COLSTR(x, SCOLOR_AUTOCMT)
#include "enums.hpp"
#include "common_consts.hpp"
#include "intel_consts.hpp"
#include "arm_consts.hpp"
#include "itypes.hpp"

#define REFRESH_ACTION_NAME "decode_instruction:Refresh"

void add_line(strvec_t &lines, const char *nm, const uint16 value)
{
  qstring s;
  s.sprnt(" %s = %#x", nm, value);
  lines.push_back(simpleline_t(s.c_str()));
}

void add_line(strvec_t &lines, const char *nm, const uint32 value)
{
  qstring s;
  s.sprnt(" %s = %#x", nm, value);
  lines.push_back(simpleline_t(s.c_str()));
}

void add_line(strvec_t &lines, const char *nm, const ea_t value)
{
  qstring s;
  s.sprnt(" %s = %#llx", nm, value);
  lines.push_back(simpleline_t(s.c_str()));
}

void add_line(strvec_t &lines, const char *nm, const char value)
{
  qstring s;
  s.sprnt(" %s = %#x", nm, value);
  lines.push_back(simpleline_t(s.c_str()));
}

void add_line(strvec_t &lines, const char *nm, const qstring &value)
{
  qstring s(" ");
  s.append(nm);
  s.append(" = ");
  s.append(value);
  lines.push_back(simpleline_t(s.c_str()));
}

static void dump_insn(const insn_t &insn, strvec_t &lines);

struct plugin_ctx_t;
struct base_action_t : public action_handler_t
{
  plugin_ctx_t &plg;
  base_action_t(plugin_ctx_t &p) : plg(p) {}

  virtual action_state_t idaapi update(action_update_ctx_t *ctx) override;
};

struct refresh_action_t : public base_action_t
{
  refresh_action_t(plugin_ctx_t &p) : base_action_t(p) {}
  virtual int idaapi activate(action_activation_ctx_t *) override;
};

struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  TWidget *widget = nullptr;
  strvec_t lines;
  int flags_lines = 0;
  int32 current_processor = 0;
  bool last_action_was_op = false;

  refresh_action_t refresh_action = refresh_action_t(*this);
  const action_desc_t refresh_action_desc = ACTION_DESC_LITERAL_PLUGMOD(
      REFRESH_ACTION_NAME,
      "Refresh View",
      &refresh_action,
      this,
      "R",
      nullptr,
      -1);

  plugin_ctx_t();
  virtual bool idaapi run(size_t) override;
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;

  ssize_t on_widget_invisible(TWidget *w);

  void refresh_view();
  bool get_current_word(bool mouse, qstring &word);
  place_t *get_place(bool mouse, int *x, int *y);
  void get_current_line(qstring *out, bool mouse, bool notags);
  ssize_t get_custom_viewer_hint(qstring *hint, TWidget *viewer, const place_t *place, int *important_lines);
};

action_state_t base_action_t::update(action_update_ctx_t *ctx)
{
  return ctx->widget == plg.widget ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
}

int idaapi refresh_action_t::activate(action_activation_ctx_t *)
{
  plg.refresh_view();
  return 1;
}

plugin_ctx_t::plugin_ctx_t()
{
  register_action(refresh_action_desc);

  addon_info_t addon_info;
  addon_info.id = "milankovo.decode_instruction";
  addon_info.name = "Decode instruction";
  addon_info.producer = "Milanek";
  addon_info.url = "https://github.com/milankovo/decode_instruction";
  addon_info.version = "1.0";
  current_processor = PH.id;
  register_addon(&addon_info);
}

void dump_operand(const op_t &op, strvec_t &lines)
{
  qstring op_details;
  op_details.sprnt("operand %d:", op.n + 1);
  lines.push_back(simpleline_t(op_details.c_str()));

  if (op.offb != 0)
    add_line(lines, "offb", op.offb);

  if (op.offo != 0)
    add_line(lines, "offo", op.offo);
  if (op.value != 0)
    add_line(lines, "value", op.value);
  if (op.flags != 0)
    add_line(lines, "flags", explain_bits(op.flags, operand_flags));
  if (op.dtype != 0)
    add_line(lines, "dtype", explain_enum(op.dtype, dtype_flags));

  if (op.type == o_reg)
  {
    switch (PH.id)
    {
    case PLFM_ARM:
    {
      // arm::registers
      add_line(lines, "reg", explain_enum(op.reg, arm::registers));
    }
    break;
    case PLFM_386:
    {

      // intel::registers
      add_line(lines, "reg", explain_enum(op.reg, intel::registers));
    }
    break;

    default:
    {
      qstring reg_name;
      auto sz = get_reg_name(&reg_name, op.reg, get_dtype_size(op.dtype));
      if (sz > 0)
      {
        reg_name.cat_sprnt(COMMENT(" // %#x"), op.reg);
        add_line(lines, "reg", reg_name);
      }
      else
        add_line(lines, "reg", op.reg);
    }
    }
  }
  else
  {
    if (op.phrase != 0)
      add_line(lines, "phrase", op.phrase);
  }
  if (op.addr != 0)
    add_line(lines, "addr", op.addr);
  if (op.type != 0)
    add_line(lines, "type", explain_enum(op.type, optype_flags));
  if (op.specflag1 != 0)
    add_line(lines, "specflag1", op.specflag1);
  if (op.specflag2 != 0)
    add_line(lines, "specflag2", op.specflag2);
  if (op.specflag3 != 0)
    add_line(lines, "specflag3", op.specflag3);
  if (op.specflag4 != 0)
    add_line(lines, "specflag4", op.specflag4);
  if (op.specval != 0)
    add_line(lines, "specval", op.specval);
}

// ----- Flag Dissection -----------------------------------------------------------------------
// We build a field model first, then render ASCII art similarly to PrintSegments in zydisinfo.

struct flag_field_t
{
  const char *id;                      // short identifier (legend letter(s))
  const char *name;                    // descriptive name
  uint32 mask;                         // raw mask (for contiguous fields)
  int shift;                           // right shift after masking
  int bitlen;                          // number of bits in the field
  bool multi_choice;                   // if true, translate value using translator; else treat as bitset
  const char *(*translator)(uint32 v); // optional value -> text
};

static const char *translate_cls(uint32 v)
{
  switch (v << 9)
  {
    /*
#define MS_CLS  0x00000600             ///< Mask for typing
#define FF_CODE 0x00000600             ///< Code ?
#define FF_DATA 0x00000400             ///< Data ?
#define FF_TAIL 0x00000200             ///< Tail ?
#define FF_UNK  0x00000000             ///< Unknown ?
    */
  case 0x0:
    return "FF_UNK" COMMENT(" // Unknown");
  case FF_TAIL:
    return "FF_TAIL" COMMENT(" // Tail");
  case FF_DATA:
    return "FF_DATA" COMMENT(" // Data");
  case FF_CODE:
    return "FF_CODE" COMMENT(" // Code");
  }
  msg("unknown class: %#x\n", v << 9);
  return "?";
}

static const char *translate_dtype(uint32 v)
{
  /*
#define FF_BYTE     0x00000000         ///< byte
#define FF_WORD     0x10000000         ///< word
#define FF_DWORD    0x20000000         ///< double word
#define FF_QWORD    0x30000000         ///< quadro word
#define FF_TBYTE    0x40000000         ///< tbyte
#define FF_STRLIT   0x50000000         ///< string literal
#define FF_STRUCT   0x60000000         ///< struct variable
#define FF_OWORD    0x70000000         ///< octaword/xmm word (16 bytes/128 bits)
#define FF_FLOAT    0x80000000         ///< float
#define FF_DOUBLE   0x90000000         ///< double
#define FF_PACKREAL 0xA0000000         ///< packed decimal real
#define FF_ALIGN    0xB0000000         ///< alignment directive
//                  0xC0000000         ///< reserved
#define FF_CUSTOM   0xD0000000         ///< custom data type
#define FF_YWORD    0xE0000000         ///< ymm word (32 bytes/256 bits)
#define FF_ZWORD    0xF0000000         ///< zmm word (64 bytes/512 bits)
*/
  switch (v << 28)
  {
  case FF_BYTE:
    return "FF_BYTE" COMMENT(" // byte");
  case FF_WORD:
    return "FF_WORD" COMMENT(" // word");
  case FF_DWORD:
    return "FF_DWORD" COMMENT(" // double word");
  case FF_QWORD:
    return "FF_QWORD" COMMENT(" // quadro word");
  case FF_TBYTE:
    return "FF_TBYTE" COMMENT(" // tbyte");
  case FF_STRLIT:
    return "FF_STRLIT" COMMENT(" // string literal");
  case FF_STRUCT:
    return "FF_STRUCT" COMMENT(" // struct variable");
  case FF_OWORD:
    return "FF_OWORD" COMMENT(" // octaword/xmm word (16 bytes/128 bits)");
  case FF_FLOAT:
    return "FF_FLOAT" COMMENT(" // float");
  case FF_DOUBLE:
    return "FF_DOUBLE" COMMENT(" // double");
  case FF_PACKREAL:
    return "FF_PACKREAL" COMMENT(" // packed decimal real");
  case FF_ALIGN:
    return "FF_ALIGN" COMMENT(" // alignment directive");
  case 0xC0000000:
    return "FF_???" COMMENT(" // reserved");
  case FF_CUSTOM:
    return "FF_CUSTOM" COMMENT(" // custom data type");
  case FF_YWORD:
    return "FF_YWORD" COMMENT(" // ymm word (32 bytes/256 bits)");
  case FF_ZWORD:
    return "FF_ZWORD" COMMENT(" // zmm word (64 bytes/512 bits)");
  }
  msg("unknown data type: %#x\n", v);
  return "?";
}

static const char *translate_optype(uint32 v)
{
  /*
#define FF_N_VOID 0x0    ///< Void (unknown)?
#define FF_N_NUMH 0x1    ///< Hexadecimal number?
#define FF_N_NUMD 0x2    ///< Decimal number?
#define FF_N_CHAR 0x3    ///< Char ('x')?
#define FF_N_SEG  0x4    ///< Segment?
#define FF_N_OFF  0x5    ///< Offset?
#define FF_N_NUMB 0x6    ///< Binary number?
#define FF_N_NUMO 0x7    ///< Octal number?
#define FF_N_ENUM 0x8    ///< Enumeration?
#define FF_N_FOP  0x9    ///< Forced operand?
#define FF_N_STRO 0xA    ///< Struct offset?
#define FF_N_STK  0xB    ///< Stack variable?
#define FF_N_FLT  0xC    ///< Floating point number?
#define FF_N_CUST 0xD    ///< Custom representation?
  */
  switch (v)
  {
  case FF_N_VOID:
    return "FF_N_VOID" COMMENT(" // Void (unknown)");
  case FF_N_NUMH:
    return "FF_N_NUMH" COMMENT(" // Hexadecimal number");
  case FF_N_NUMD:
    return "FF_N_NUMD" COMMENT(" // Decimal number");
  case FF_N_CHAR:
    return "FF_N_CHAR" COMMENT(" // Char ('x')");
  case FF_N_SEG:
    return "FF_N_SEG" COMMENT(" // Segment");
  case FF_N_OFF:
    return "FF_N_OFF" COMMENT(" // Offset");
  case FF_N_NUMB:
    return "FF_N_NUMB" COMMENT(" // Binary number");
  case FF_N_NUMO:
    return "FF_N_NUMO" COMMENT(" // Octal number");
  case FF_N_ENUM:
    return "FF_N_ENUM" COMMENT(" // Enumeration");
  case FF_N_FOP:
    return "FF_N_FOP" COMMENT(" // Forced operand");
  case FF_N_STRO:
    return "FF_N_STRO" COMMENT(" // Struct offset");
  case FF_N_STK:
    return "FF_N_STK" COMMENT(" // Stack variable");
  case FF_N_FLT:
    return "FF_N_FLT" COMMENT(" // Floating point number");
  case FF_N_CUST:
    return "FF_N_CUST" COMMENT(" // Custom representation");
  }
  return "?";
}

// Build layer line for highlighting a specific nibble group; char_code is printed for bits in mask.
// (removed unused layer_line function)

// Extract and render.
static void dissect_flags_verbose(flags64_t flags, strvec_t &lines)
{
  // Use flag_field_t style descriptors to describe each logical element.
  // Group header order (high->low) matches bits.md visual.
  enum group_idx
  {
    G_U1 = 0, // highest nibble
    G_U2,     // second highest nibble
    G_OP8,
    G_OP7,
    G_OP6,
    G_OP5,
    G_OP4,
    G_OP3,
    G_DTYPE,
    G_OP2,
    G_OP1,
    G_A_HI,
    G_A_LO,
    G_ACCV,
    G_B_HI,
    G_B_LO,
    G_COUNT
  };
  const char *groups[G_COUNT] = {
      "UUUU", "UUUU", "8888", "7777", "6666", "5555", "4444", "3333", "DDDD", "2222", "1111", "AAAA", "AAAA", "ACCV", "BBBB", "BBBB"};
  // We'll decide later which leading groups to omit (all-zero & no lines).

  struct field_descriptor
  {
    const char *label;                 // printable name
    uint64 mask;                       // bit mask
    int shift;                         // shift if extracting multi-bit value
    int bitlen;                        // length (for formatting)
    group_idx group;                   // anchor group for colon ladder
    const char *(*translator)(uint32); // optional translator
    bool always_show;                  // show even if value==0
    uchar color;                       // COLOR_* value for rendering
  };

  // Operand nibble masks helper
  auto op_mask = [](int idx) -> uint64
  { return 0xFULL << get_operand_type_shift(idx); };

  // Build descriptors
  field_descriptor base_fields[] = {
      {"unused", 0xFF00000000000000ULL, 56, 8, G_U2, nullptr, false, COLOR_DEFAULT},
      {"op8", op_mask(7), get_operand_type_shift(7), 4, G_OP8, translate_optype, false, COLOR_REG},
      {"op7", op_mask(6), get_operand_type_shift(6), 4, G_OP7, translate_optype, false, COLOR_REG},
      {"op6", op_mask(5), get_operand_type_shift(5), 4, G_OP6, translate_optype, false, COLOR_REG},
      {"op5", op_mask(4), get_operand_type_shift(4), 4, G_OP5, translate_optype, false, COLOR_REG},
      {"op4", op_mask(3), get_operand_type_shift(3), 4, G_OP4, translate_optype, false, COLOR_REG},
      {"op3", op_mask(2), get_operand_type_shift(2), 4, G_OP3, translate_optype, false, COLOR_REG},
      {"dtype", 0xF0000000ULL, 28, 4, G_DTYPE, translate_dtype, true, COLOR_ASMDIR},
      {"op2", op_mask(1), get_operand_type_shift(1), 4, G_OP2, translate_optype, false, COLOR_REG},
      {"op1", op_mask(0), get_operand_type_shift(0), 4, G_OP1, translate_optype, false, COLOR_REG},

      /*
      #define FF_COMM   0x00000800            ///< Has comment?
#define FF_REF    0x00001000            ///< has references
#define FF_LINE   0x00002000            ///< Has next or prev lines?
#define FF_NAME   0x00004000            ///< Has name?
#define FF_LABL   0x00008000            ///< Has dummy name?
#define FF_FLOW   0x00010000            ///< Exec flow from prev instruction
#define FF_SIGN   0x00020000            ///< Inverted sign of operands
#define FF_BNOT   0x00040000            ///< Bitwise negation of operands
#define FF_UNUSED 0x00080000           ///< unused bit (was used for variable bytes)
      */
      {"FF_COMM" COMMENT(" // has comment?"), 0x00000800ULL, 11, 1, G_A_LO, nullptr, false, COLOR_CREFTAIL},
      {"FF_REF" COMMENT(" // has references"), 0x00001000ULL, 12, 1, G_A_LO, nullptr, false, COLOR_DATNAME},
      {"FF_LINE" COMMENT(" // has next or prev lines?"), 0x00002000ULL, 13, 1, G_A_LO, nullptr, false, COLOR_DEFAULT},
      {"FF_NAME" COMMENT(" // has name?"), 0x00004000ULL, 14, 1, G_A_LO, nullptr, false, COLOR_DCHAR},
      {"FF_LABL" COMMENT(" // has dummy name?"), 0x00008000ULL, 15, 1, G_A_LO, nullptr, false, COLOR_DNAME},

      {"FF_FLOW" COMMENT(" // Exec flow from prev instruction"), 0x00010000ULL, 16, 1, G_A_HI, nullptr, false, COLOR_CHAR},
      {"FF_SIGN" COMMENT(" // Inverted sign of operands"), 0x00020000ULL, 17, 1, G_A_HI, nullptr, false, COLOR_IMPNAME},
      {"FF_BNOT" COMMENT(" // Bitwise negation of operands"), 0x00040000ULL, 18, 1, G_A_HI, nullptr, false, COLOR_LIBNAME},
      {"FF_UNUSED" COMMENT(" // unused bit (was used for variable bytes)"), 0x00080000ULL, 19, 1, G_A_HI, nullptr, false, COLOR_LOCNAME},
      {"MS_CLS", 0x00000600ULL, 9, 2, G_ACCV, translate_cls, true, COLOR_MACRO},
      {"FF_IVL" COMMENT(" // Byte has a value"), 0x00000100ULL, 8, 1, G_ACCV, nullptr, true, COLOR_NUMBER},
      {"byte", 0x000000FFULL, 0, 8, G_B_HI, nullptr, true, COLOR_NUMBER},
  };

  // Code overlay bits separate lines (attach to dtype group for context)
  struct bit_name
  {
    uint32 bit;
    const char *nm;
    group_idx grp;
    uchar color;
  };
  /*
  #define FF_FUNC 0x10000000             ///< function start?
//              0x20000000             // not used
#define FF_IMMD 0x40000000             ///< Has Immediate value ?
#define FF_JUMP 0x80000000             ///< Has jump table or switch_info?
  */
  const bit_name code_bits[] = {
      {0x10000000, "FF_FUNC" COMMENT(" // function start?"), G_DTYPE, COLOR_IMPNAME},
      {0x40000000, "FF_IMMD" COMMENT(" // Has Immediate value?"), G_DTYPE, COLOR_MACRO},
      {0x20000000, "FF_UNUSED" COMMENT(" // not used"), G_DTYPE, COLOR_CREFTAIL},
      {0x80000000, "FF_JUMP" COMMENT(" // Has jump table or switch_info?"), G_DTYPE, COLOR_COLLAPSED}};

  // We will build group_cols after trimming.
  qvector<int> group_cols;
  qstring header; // final header after trimming
  int header_len = 0;

  struct rendered_line
  {
    int group;
    qstring text;
    int order;
    int order_bit;   // for sorting (usually LSB of field)
    int display_bit; // bit whose column we keep for the vertical ladder (MSB for small multi-bit fields)
    int column_pos;  // computed after header build
    uchar color;     // COLOR_* value
    int start_bit;   // LSB bit index of the field
    int bitlen;      // field bit length
  };
  qvector<rendered_line> out_lines;

  auto add_field_line = [&](const field_descriptor &fd)
  {
    uint64 raw = (flags & fd.mask) >> fd.shift;
    if (!fd.always_show && raw == 0)
      return;
    qstring valtxt;
    if (fd.translator)
      valtxt.sprnt("%s", fd.translator((uint32)raw));
    else
    {
      if (fd.bitlen == 1)
      {
        if (raw == 0 && !fd.always_show)
          return; // would have been skipped anyway
        // omit '=1' for single-bit set flags; if always_show and raw==0 show '=0'
        if (raw == 0 && fd.always_show)
          valtxt.sprnt("0");
        else
          valtxt.clear(); // indicates we will print only label
      }
      else
        valtxt.sprnt("0x%llX", raw);
    }
    qstring line;
    if (fd.bitlen == 1 && valtxt.empty() && !fd.translator && !(fd.always_show && raw == 0))
      line.sprnt("%s", fd.label);
    else
      line.sprnt("%s=%s", fd.label, valtxt.c_str());
    // Real positions: order by lowest bit; enumerated (translator != nullptr) anchor under leftmost (MSB)
    int order_bit = fd.shift; // LSB position
    int display_bit;
    if (strcmp(fd.label, "byte") == 0)
      display_bit = fd.shift + fd.bitlen - 1; // anchor combined byte at MSB
    else if (fd.bitlen > 1 && fd.translator != nullptr)
      display_bit = fd.shift + fd.bitlen - 1; // MSB anchor for enums
    else
      display_bit = fd.shift; // actual bit for single-bit or raw multi-bit fields
    out_lines.push_back({fd.group, line, fd.group, order_bit, display_bit, -1, fd.color, fd.shift, fd.bitlen});
  };

  for (auto &f : base_fields)
  {
    // Determine class to gate DT_TYPE vs MS_CODE usage
    uint64 cls_bits = (flags & 0x00000600ULL);    // MS_CLS
    bool is_code_cls = cls_bits == 0x00000600ULL; // FF_CODE
    bool is_data_cls = cls_bits == 0x00000400ULL; // FF_DATA
    if (strcmp(f.label, "dtype") == 0 && !is_data_cls)
      continue; // show dtype only for data class
    if (strcmp(f.label, "byte") == 0 && (flags & 0x00000100ULL) == 0)
      continue; // hide byte field when FF_IVL is 0
    add_field_line(f);
  }

  // Code bits (only meaningful if class is FF_CODE)
  if ((flags & 0x00000600ULL) == 0x00000600ULL)
  {
    for (auto &cb : code_bits)
      if (flags & cb.bit)
      {
        // compute bit position
        int bitpos = -1;
        for (int b = 0; b < 64; ++b)
        {
          if ((uint64)cb.bit & (1ULL << b))
          {
            bitpos = b;
            break;
          }
        }
        if (bitpos < 0)
          bitpos = 0;
        // code bits: single-bit real position
        out_lines.push_back({cb.grp, qstring().sprnt("%s", cb.nm), cb.grp, bitpos, bitpos, -1, cb.color, bitpos, 1});
      }
  }

  // Sort by order_bit ascending (lower bit first). If tie, group then text.
  std::sort(out_lines.begin(), out_lines.end(), [](const rendered_line &a, const rendered_line &b)
            {
              if (a.order_bit != b.order_bit)
                return a.order_bit < b.order_bit;
              if (a.group != b.group)
                return a.group < b.group;
              return strcmp(a.text.c_str(), b.text.c_str()) < 0; });
  // Determine which groups have at least one line anchor
  bool group_has_line[G_COUNT] = {false};
  for (auto &rlchk : out_lines)
    if (rlchk.group >= 0 && rlchk.group < G_COUNT)
      group_has_line[rlchk.group] = true;

  // Helper to test if all nibbles of group are zero
  int group_bit_index[G_COUNT] = {60, 56, 52, 48, 44, 40, 36, 32, 28, 24, 20, 16, 12, 8, 4, 0};

  auto group_all_zero = [&](int gi) -> bool
  {
    uint64 nib = (flags >> group_bit_index[gi]) & 0xFULL;
    return nib == 0ULL;
  };

  // Find first group to display: first group that (a) has a line OR (b) not all zero and later groups need context.
  int first_group = 0;
  for (int gi = 0; gi < G_COUNT; ++gi)
  {
    if (group_has_line[gi] || !group_all_zero(gi))
    {
      first_group = gi;
      break;
    }
  }

  // Build header & group_cols from first_group onward
  int col = 0;
  for (int gi = first_group; gi < G_COUNT; ++gi)
  {
    if (gi != first_group)
    {
      header += ' ';
      col += 1;
    }
    group_cols.push_back(col); // map index (gi-first_group) to column
    header += groups[gi];
    col += (int)strlen(groups[gi]);
  }
  header_len = header.length();
  lines.push_back(simpleline_t(header.c_str()));

  // Build bit line for displayed groups
  qstring bit_line;
  for (int gi = first_group; gi < G_COUNT; ++gi)
  {
    if (gi != first_group)
      bit_line += ' ';
    uint64 nib = (flags >> group_bit_index[gi]) & 0xFULL;
    for (int b = 3; b >= 0; --b)
      bit_line += ((nib >> b) & 1) ? '1' : '0';
  }
  // If FF_IVL (0x00000100) is not set, mask out the combined byte field bits (bits 0-7) with '?'
  if ((flags & 0x00000100ULL) == 0)
  {
    auto mask_nibble = [&](int gidx)
    {
      if (gidx < first_group)
        return;
      int idx = gidx - first_group;
      if (idx < 0 || idx >= (int)group_cols.size())
        return;
      int col = group_cols[idx];
      // Replace four characters (nibble) with '?', skipping inter-group spaces
      for (int i = 0; i < 4; ++i)
      {
        int pos = col + i;
        if (pos >= 0 && pos < (int)bit_line.length())
        {
          char &c = bit_line[pos];
          if (c == '0' || c == '1')
            c = '?';
        }
      }
    };
    // High and low nibble of first byte
    mask_nibble(G_B_HI);
    mask_nibble(G_B_LO);
  }
  // We'll colorize the bit_line after computing per-bit colors; store plain for now.
  qstring plain_bit_line = bit_line;

  // Compute column position for each line's display_bit now that header/group cols known
  for (auto &rl : out_lines)
  {
    // Find group containing display_bit
    for (int gi = first_group; gi < G_COUNT; ++gi)
    {
      int low = group_bit_index[gi];
      int high = low + 3;
      if (rl.display_bit >= low && rl.display_bit <= high)
      {
        int idx = gi - first_group;
        int offset = (low + 3) - rl.display_bit; // 0..3
        rl.column_pos = group_cols[idx] + offset;
        break;
      }
    }
  }

  // Build per-column bit colors using first-writer strategy
  qvector<uchar> column_bit_color;
  column_bit_color.resize(header_len, COLOR_DEFAULT);
  auto bit_to_column = [&](int bitpos) -> int
  {
    for (int gi = first_group; gi < G_COUNT; ++gi)
    {
      int low = group_bit_index[gi];
      int high = low + 3;
      if (bitpos >= low && bitpos <= high)
      {
        int idx = gi - first_group;
        int offset = (low + 3) - bitpos; // 0..3
        return group_cols[idx] + offset;
      }
    }
    return -1;
  };
  for (auto &rlc : out_lines)
  {
    for (int off = 0; off < rlc.bitlen; ++off)
    {
      int bitpos = rlc.start_bit + off;
      int colpos = bit_to_column(bitpos);
      if (colpos >= 0 && colpos < header_len && column_bit_color[colpos] == COLOR_DEFAULT)
        column_bit_color[colpos] = rlc.color;
    }
  }

  // Light color for unknown byte bits ('?') when FF_IVL is not set
  if ((flags & 0x00000100ULL) == 0) // FF_IVL missing
  {
    for (int bit = 0; bit < 8; ++bit)
    {
      int colpos = bit_to_column(bit);
      if (colpos >= 0 && colpos < header_len)
        column_bit_color[colpos] = COLOR_AUTOCMT; // chosen subtle/light color
    }
  }

  // Emit colored bit line
  {
    qstring colored;
    int cur = -1;
    for (int i = 0; i < header_len; ++i)
    {
      char ch = (i < (int)plain_bit_line.length()) ? plain_bit_line[i] : ' ';
      uchar want = (ch == '0' || ch == '1') ? column_bit_color[i] : COLOR_DEFAULT;
      if (want != cur)
      {
        colored += COLOR_ON;
        colored += (char)want;
        cur = want;
      }
      colored += ch;
    }
    if (cur != COLOR_DEFAULT)
    {
      colored += COLOR_ON;
      colored += (char)COLOR_DEFAULT;
    }
    lines.push_back(simpleline_t(colored.c_str()));
  }

  // Render lines (color vertical ladder segments and labels)
  for (auto &rl : out_lines)
  {
    if (rl.group < first_group)
      continue; // trimmed away
    qstring row(header_len, ' ');
    int anchor_pos = rl.column_pos < 0 ? 0 : rl.column_pos;
    // Determine threshold: keep vertical lines for all lines with order_bit >= current line's order_bit
    for (auto &rl2 : out_lines)
    {
      if (rl2.order_bit >= rl.order_bit && rl2.column_pos >= 0 && rl2.column_pos < header_len)
        row[rl2.column_pos] = ':';
    }
    // Shrink trailing spaces to anchor
    if ((int)row.length() > anchor_pos + 1)
      row.resize(anchor_pos + 1);
    qstring label;
    label.sprnt(".. %s", rl.text.c_str());
    // Colorize the "field=value" portion (skip the ".. ")
    // Build colored ladder: color colons by field owning that column
    qstring colored_ladder;
    int curc = -1;
    for (int i = 0; i < (int)row.length(); ++i)
    {
      char c = row[i];
      uchar want = (c == ':') ? column_bit_color[i] : COLOR_DEFAULT;
      if (want != curc)
      {
        colored_ladder += COLOR_ON;
        colored_ladder += (char)want;
        curc = want;
      }
      colored_ladder += c;
    }
    if (curc != COLOR_DEFAULT)
    {
      colored_ladder += COLOR_ON;
      colored_ladder += (char)COLOR_DEFAULT;
    }
    // Append label in its field color
    colored_ladder += COLOR_ON;
    colored_ladder += (char)rl.color;
    colored_ladder += label;
    colored_ladder += COLOR_OFF;
    colored_ladder += (char)rl.color;
    lines.push_back(simpleline_t(colored_ladder.c_str()));
  }
}

place_t *plugin_ctx_t::get_place(
    bool mouse = false,
    int *x = 0,
    int *y = 0)
{
  return widget == nullptr ? nullptr : get_custom_viewer_place(widget, mouse, x, y);
}

bool plugin_ctx_t::get_current_word(bool mouse, qstring &word)
{
  // query the cursor position
  int x, y;
  if (get_place(mouse, &x, &y) == nullptr)
    return false;

  // query the line at the cursor
  qstring qline;
  get_current_line(&qline, mouse, true);
  const char *line = qline.begin();
  if (line == nullptr)
    return false;

  if (x >= (int)qstrlen(line))
    return false;

  // find the beginning of the word
  const char *ptr = line + x;
  while (ptr > line && !qisspace(ptr[-1]))
    ptr--;

  // find the end of the word
  const char *begin = ptr;
  ptr = line + x;
  while (!qisspace(*ptr) && *ptr != '\0')
    ptr++;

  word.qclear();
  word.append(begin, ptr - begin);
  return true;
}

void plugin_ctx_t::get_current_line(qstring *out, bool mouse, bool notags)
{
  *out = get_custom_viewer_curline(widget, mouse);
  if (notags)
    tag_remove(out);
}

void plugin_ctx_t::refresh_view()
{
  if (!widget)
    return;
  lines.qclear();

  ea_t ea = get_screen_ea();

  // Dissect flags visually, only showing set fields
  dissect_flags_verbose(get_full_flags(ea), lines);
  this->flags_lines = lines.size();

  lines.push_back(simpleline_t("")); // empty line

  insn_t insn;
  if (decode_insn(&insn, ea) > 0)
  {
    qstring disasm;
    generate_disasm_line(&disasm, ea, GENDSM_FORCE_CODE | GENDSM_MULTI_LINE);
    lines.push_back(simpleline_t(disasm.c_str()));

    dump_insn(insn, lines);

    for (int i = 0; i < UA_MAXOP && insn.ops[i].type != o_void; ++i)
    {
      dump_operand(insn.ops[i], lines);
    }
  }
  else
  {
    lines.push_back(simpleline_t("Failed to decode instruction."));
  }

  refresh_custom_viewer(widget);
}

ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list va)
{
  // msg("on_event: %d\n", code);

  switch (code)
  {
  case ui_preprocess_action:
  {
    ///< cb: ida ui is about to handle a user action.
    ///< \param name  (const char *) ui action name.
    ///<                             these names can be looked up in ida[tg]ui.cfg
    ///< \retval 0 ok
    ///< \retval nonzero a plugin has handled the command
    const char *name = va_arg(va, const char *);
    last_action_was_op = (name != nullptr && memcmp(name, "Op", 2) == 0);
    return 0;
  }
  case ui_postprocess_action:
  {
    if (last_action_was_op)
    {
      refresh_view();
      last_action_was_op = false;
    }
    return 0;
  }
  case ui_get_custom_viewer_hint:
  {
    qstring *hint = va_arg(va, qstring *);
    TWidget *viewer = va_arg(va, TWidget *);
    const place_t *place = va_arg(va, const place_t *);
    int *important_lines = va_arg(va, int *);
    return get_custom_viewer_hint(hint, viewer, place, important_lines);
  }

  case ui_screen_ea_changed:
    ///< cb: The "current address" changed
    ///< \param ea          (ea_t)
    ///< \param prev_ea     (ea_t)
    ///< \return void
    refresh_view();
    break;

  case ui_widget_invisible:
  {
    return on_widget_invisible(va_arg(va, TWidget *));
  }
  } // switch
  return 0;
}

ssize_t plugin_ctx_t::on_widget_invisible(TWidget *w)
{
  if (w != widget)
    return 0;

  widget = nullptr;
  lines.qclear();
  unhook_event_listener(HT_UI, this);
  return 0;
}

///< cb: ui wants to display a hint for a viewer (idaview or custom).
///< Every subscriber is supposed to append the hint lines
///< to HINT and increment IMPORTANT_LINES accordingly.
///< Completely overwriting the existing lines in HINT
///< is possible but not recommended.
///< If the REG_HINTS_MARKER sequence is found in the
///< returned hints string, it will be replaced with the
///< contents of the "regular" hints.
///< If the SRCDBG_HINTS_MARKER sequence is found in the
///< returned hints string, it will be replaced with the
///< contents of the source-level debugger-generated hints.
///< The following keywords might appear at the beginning of the
///< returned hints:
///< HIGHLIGHT text\n
///<   where text will be highlighted
///< CAPTION caption\n
///<   caption for the hint widget
///< \param[out] hint             (::qstring *) the output string,
///<                              on input contains hints from the previous subscribes
///< \param viewer                (TWidget*) viewer
///< \param place                 (::place_t *) current position in the viewer
///< \param[out] important_lines  (int *) number of important lines,
///<                                     should be incremented,
///<                                     if zero, the result is ignored
///< \retval 0 continue collecting hints with other subscribers
///< \retval 1 stop collecting hints
ssize_t plugin_ctx_t::get_custom_viewer_hint(qstring *hint, TWidget *viewer, const place_t *place, int *important_lines)
{
  if (viewer != this->widget)
    return 0; // not our viewer

  if (place == nullptr)
    return 0;

  auto spl = static_cast<const simpleline_place_t *>(place);

  msg("lnnum: %d flags_lines: %d\n", spl->n, this->flags_lines);
  if (spl->n < this->flags_lines)
  {
    hint->append("Flags hints:\n");
    hint->append(" B ... byte value\n");
    hint->append(" V ... value defined\n");
    hint->append(" C ... Byte state\n");
    hint->append(" A ... Common State Info\n");
    hint->append(" D ... data type / code bits\n");
    hint->append(" 1 ... operand 1\n");
    hint->append(" 2 ... operand 2\n");
    hint->append(" 3 ... operand 3\n");
    hint->append(" 4 ... operand 4\n");
    hint->append(" 5 ... operand 5\n");
    hint->append(" 6 ... operand 6\n");
    hint->append(" 7 ... operand 7\n");
    hint->append(" 8 ... operand 8\n");
    hint->append(" U ... unused\n");
    *important_lines += 15;
  }

  qstring word;
  get_current_word(true, word);
  msg("word under cursor: %s", word.c_str());

  return 0;
}

bool idaapi plugin_ctx_t::run(size_t)
{
  if (widget)
  {
    activate_widget(widget, true);
    return true;
  }

  simpleline_place_t s1, s2;

  widget = create_custom_viewer("Item details", &s1, &s2, &s1, nullptr, &lines, nullptr, this);
  if (!widget)
    return false;

  hook_event_listener(HT_UI, this);
  // hook_event_listener(HT_IDP, this);

  display_widget(widget, WOPN_DP_TAB | WOPN_RESTORE, "Functions");
  attach_action_to_popup(widget, nullptr, REFRESH_ACTION_NAME);
  refresh_view();
  return true;
}

static void dump_insn(const insn_t &insn, strvec_t &lines)
{
  add_line(lines, "size", insn.size);

  add_line(lines, "cs", insn.cs);
  add_line(lines, "ip", insn.ip);
  add_line(lines, "ea", insn.ea);
  auto ph_id = PH.id;

  add_line(lines, "itype", get_instruction_name(ph_id, insn.itype));

  if (ph_id == PLFM_386)
  {
    add_line(lines, "auxpref", explain_bits(insn.auxpref, intel::auxpref_flags));
  }
  else if (ph_id == PLFM_ARM)
  {
    add_line(lines, "auxpref", explain_bits(insn.auxpref, arm::auxpref_flags));
  }
  else
  {
    add_line(lines, "auxpref", insn.auxpref);
  }

  if (insn.segpref != 0)
    add_line(lines, "segpref", insn.segpref);

  if (insn.insnpref != 0)
    add_line(lines, "insnpref", insn.insnpref);

  qstring flags_desc;
  add_line(lines, "flags", explain_bits(insn.flags, insn_flags));
}

static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "Decode Instruction Plugin",
    "",
    "Decode Instruction",
    ""};