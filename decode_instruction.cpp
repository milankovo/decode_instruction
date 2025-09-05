// decode_instruction.cpp
// Custom plugin to decode and display instruction details
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#define BYTES_SOURCE 1
#include <bytes.hpp>
#include <bitset>

#define REFRESH_ACTION_NAME "decode_instruction:Refresh"

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
  void refresh_view();
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
}

void dump_operand(const op_t &op, strvec_t &lines)
{
  qstring op_details;
  op_details.sprnt("operand %d: type=%d, value=%llX", op.n + 1, op.type, op.value);
  lines.push_back(simpleline_t(op_details.c_str()));

  auto add_line = [&lines](const char *nm, const qstring &ln)
  {
    qstring formatted_line;
    formatted_line.sprnt(" %s = %s", nm, ln.c_str());
    lines.push_back(simpleline_t(formatted_line.c_str()));
  };

  if (op.offb != 0)
    add_line("offb", qstring().sprnt("%#x", static_cast<unsigned>(op.offb)));

  if (op.offo != 0)
    add_line("offo", qstring().sprnt("%#x", static_cast<unsigned>(op.offo)));
  if (op.value != 0)
    add_line("value", qstring().sprnt("%#llx", static_cast<unsigned long long>(op.value)));
  if (op.flags != 0)
    add_line("flags", qstring().sprnt("%#x", static_cast<unsigned>(op.flags)));
  if (op.dtype != 0)
    add_line("dtype", qstring().sprnt("%#x", static_cast<unsigned>(op.dtype)));
  if (op.reg != 0)
    add_line("reg", qstring().sprnt("%#x", static_cast<unsigned>(op.reg)));
  if (op.phrase != 0)
    add_line("phrase", qstring().sprnt("%#x", static_cast<unsigned>(op.phrase)));
  if (op.addr != 0)
    add_line("addr", qstring().sprnt("%#llx", static_cast<unsigned long long>(op.addr)));
  if (op.type != 0)
    add_line("type", qstring().sprnt("%#x", static_cast<unsigned>(op.type)));
  if (op.specflag1 != 0)
    add_line("specflag1", qstring().sprnt("%#x", static_cast<unsigned>(op.specflag1)));
  if (op.specflag2 != 0)
    add_line("specflag2", qstring().sprnt("%#x", static_cast<unsigned>(op.specflag2)));
  if (op.specflag3 != 0)
    add_line("specflag3", qstring().sprnt("%#x", static_cast<unsigned>(op.specflag3)));
  if (op.specflag4 != 0)
    add_line("specflag4", qstring().sprnt("%#x", static_cast<unsigned>(op.specflag4)));
  if (op.specval != 0)
    add_line("specval", qstring().sprnt("%#x", static_cast<unsigned>(op.specval)));
  if (op.shown())
  {
    add_line("shown", "true");
  }
}

void dump_flags(const flags64_t &flags, strvec_t &lines)
{
  qstring features = " ";
  auto add_line = [&features](const char *nm)
  {
    if (features.length() > 1)
      features += qstring().sprnt(", %s", nm);
    else
      features += qstring().sprnt("%s", nm);
  };

  lines.push_back(simpleline_t(qstring().sprnt("Flags: %#llx", static_cast<unsigned long long>(flags))));

  if (is_code(flags))
    add_line("is_code");
  if (is_data(flags))
    add_line("is_data");
  if (is_tail(flags))
    add_line("is_tail");
  if (is_unknown(flags))
    add_line("is_unknown");
  if (has_any_name(flags))
    add_line("has_any_name");
  if (is_flow(flags))
    add_line("is_flow");
  if (has_extra_cmts(flags))
    add_line("has_extra_cmts");
  if (has_cmt(flags))
    add_line("has_cmt");
  if (has_xref(flags))
    add_line("has_xref");
  if (has_name(flags))
    add_line("has_name");
  if (has_dummy_name(flags))
    add_line("has_dummy_name");
  if (has_user_name(flags))
    add_line("has_user_name");
  if (is_byte(flags))
    add_line("is_byte");
  if (is_word(flags))
    add_line("is_word");
  if (is_dword(flags))
    add_line("is_dword");
  if (is_qword(flags))
    add_line("is_qword");
  if (is_oword(flags))
    add_line("is_oword");
  if (is_yword(flags))
    add_line("is_yword");
  if (is_zword(flags))
    add_line("is_zword");
  if (is_tbyte(flags))
    add_line("is_tbyte");
  if (is_float(flags))
    add_line("is_float");
  if (is_double(flags))
    add_line("is_double");
  if (is_pack_real(flags))
    add_line("is_pack_real");
  if (is_strlit(flags))
    add_line("is_strlit");
  if (is_struct(flags))
    add_line("is_struct");
  if (is_align(flags))
    add_line("is_align");
  if (is_custom(flags))
    add_line("is_custom");
  if (has_immd(flags))
    add_line("has_immd");
  if (is_func(flags))
    add_line("is_func");
  if ((flags & FF_JUMP) != 0)
    add_line("Has jump table or switch_info");

  lines.push_back(simpleline_t(features.c_str()));
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
  switch (v)
  {
  case 0x0:
    return "FF_UNK"; // unknown (only reported if value-defined bit absent too)
  case 0x2 >> 1:
    return "FF_TAIL";
  case 0x4 >> 1:
    return "FF_DATA";
  case 0x6 >> 1:
    return "FF_CODE";
  }
  msg("unknown class: %#x\n", v);
  return "?";
}

static const char *translate_dtype(uint32 v)
{
  switch (v)
  {
  case 0x0:
    return "FF_BYTE";
  case 0x1:
    return "FF_WORD";
  case 0x2:
    return "FF_DWORD";
  case 0x3:
    return "FF_QWORD";
  case 0x4:
    return "FF_TBYTE";
  case 0x5:
    return "FF_STRLIT";
  case 0x6:
    return "FF_STRUCT";
  case 0x7:
    return "FF_OWORD";
  case 0x8:
    return "FF_FLOAT";
  case 0x9:
    return "FF_DOUBLE";
  case 0xA:
    return "FF_PACKREAL";
  case 0xB:
    return "FF_ALIGN";
  case 0xD:
    return "FF_CUSTOM";
  case 0xE:
    return "FF_YWORD";
  case 0xF:
    return "FF_ZWORD";
  }
  return "?";
}

static const char *translate_optype(uint32 v)
{
  switch (v)
  {
  case 0x0:
    return "VOID";
  case 0x1:
    return "NUMH";
  case 0x2:
    return "NUMD";
  case 0x3:
    return "CHAR";
  case 0x4:
    return "SEG";
  case 0x5:
    return "OFF";
  case 0x6:
    return "NUMB";
  case 0x7:
    return "NUMO";
  case 0x8:
    return "ENUM";
  case 0x9:
    return "FOP";
  case 0xA:
    return "STRO";
  case 0xB:
    return "STK";
  case 0xC:
    return "FLT";
  case 0xD:
    return "CUST";
  }
  return "?";
}

// Build operand field specs dynamically for 8 operands (nibbles). Start from operand1 at bit 20.
struct dissect_result_t
{
  qvector<qstring> art_lines; // ASCII art rows
  strvec_t legend_lines;      // textual decoded info
};

// Generate a 64-bit binary string grouped by nibble.
static qstring make_bit_string_64(flags64_t flags)
{
  std::bitset<64> bits(flags);
  qstring out;
  for (int i = 63; i >= 0; --i)
  {
    out += bits[i] ? '1' : '0';
    if (i % 4 == 0 && i != 0)
      out += ' ';
  }
  return out;
}

// Build layer line for highlighting a specific nibble group; char_code is printed for bits in mask.
static qstring layer_line(flags64_t flags, uint64 mask, char ch)
{
  qstring line;
  for (int bit = 63; bit >= 0; --bit)
  {
    if (bit % 4 == 3 && bit != 63)
      line += ' ';
    uint64 bitmask = 1ULL << bit;
    line += (mask & bitmask) ? ch : '0';
  }
  return line;
}

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
  qstring full_bit_line = make_bit_string_64(flags);

  struct field_descriptor
  {
    const char *label;                 // printable name
    uint64 mask;                       // bit mask
    int shift;                         // shift if extracting multi-bit value
    int bitlen;                        // length (for formatting)
    group_idx group;                   // anchor group for colon ladder
    const char *(*translator)(uint32); // optional translator
    bool always_show;                  // show even if value==0
  };

  // Operand nibble masks helper
  auto op_mask = [](int idx) -> uint64
  { return 0xFULL << get_operand_type_shift(idx); };

  // Build descriptors
  field_descriptor base_fields[] = {
      {"unused", 0xFF00000000000000ULL, 56, 8, G_U2, nullptr, false},
      {"op8", op_mask(7), get_operand_type_shift(7), 4, G_OP8, translate_optype, false},
      {"op7", op_mask(6), get_operand_type_shift(6), 4, G_OP7, translate_optype, false},
      {"op6", op_mask(5), get_operand_type_shift(5), 4, G_OP6, translate_optype, false},
      {"op5", op_mask(4), get_operand_type_shift(4), 4, G_OP5, translate_optype, false},
      {"op4", op_mask(3), get_operand_type_shift(3), 4, G_OP4, translate_optype, false},
      {"op3", op_mask(2), get_operand_type_shift(2), 4, G_OP3, translate_optype, false},
      {"dtype", 0xF0000000ULL, 28, 4, G_DTYPE, translate_dtype, true},
      {"op2", op_mask(1), get_operand_type_shift(1), 4, G_OP2, translate_optype, false},
      {"op1", op_mask(0), get_operand_type_shift(0), 4, G_OP1, translate_optype, false},
      // Individual MS_COMM bits (low part)
      {"FF_COMM", 0x00000800ULL, 11, 1, G_A_LO, nullptr, false},
      {"FF_REF", 0x00001000ULL, 12, 1, G_A_LO, nullptr, false},
      {"FF_LINE", 0x00002000ULL, 13, 1, G_A_LO, nullptr, false},
      {"FF_NAME", 0x00004000ULL, 14, 1, G_A_LO, nullptr, false},
      {"FF_LABL", 0x00008000ULL, 15, 1, G_A_LO, nullptr, false},
      // Individual MS_COMM bits (high part)
      {"FF_FLOW", 0x00010000ULL, 16, 1, G_A_HI, nullptr, false},
      {"FF_SIGN", 0x00020000ULL, 17, 1, G_A_HI, nullptr, false},
      {"FF_BNOT", 0x00040000ULL, 18, 1, G_A_HI, nullptr, false},
      {"FF_UNUSED", 0x00080000ULL, 19, 1, G_A_HI, nullptr, false},
      {"MS_CLS", 0x00000600ULL, 9, 2, G_ACCV, translate_cls, true},
      {"FF_IVL", 0x00000100ULL, 8, 1, G_ACCV, nullptr, true},
      {"byte_hi", 0x000000F0ULL, 4, 4, G_B_HI, nullptr, true},
      {"byte_lo", 0x0000000FULL, 0, 4, G_B_LO, nullptr, true},
  };

  // Code overlay bits separate lines (attach to dtype group for context)
  struct bit_name
  {
    uint32 bit;
    const char *nm;
    group_idx grp;
  };
  const bit_name code_bits[] = {
      {0x10000000, "FF_FUNC", G_DTYPE}, {0x40000000, "FF_IMMD", G_DTYPE}, {0x80000000, "FF_JUMP", G_DTYPE}};

  // We will build group_cols after trimming.
  qvector<int> group_cols;
  qstring header; // final header after trimming
  int header_len = 0;

  struct rendered_line
  {
    int group;
    qstring text;
    int order;
  int order_bit;    // for sorting (usually LSB of field)
  int display_bit;  // bit whose column we keep for the vertical ladder (MSB for small multi-bit fields)
  int column_pos;   // computed after header build
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
        valtxt.sprnt("%llu", raw);
      else
        valtxt.sprnt("0x%llX", raw);
    }
    qstring line;
    line.sprnt("%s=%s", fd.label, valtxt.c_str());
    // Real positions: order by lowest bit; enumerated (translator != nullptr) anchor under leftmost (MSB)
    int order_bit = fd.shift; // LSB position
    int display_bit;
    if (fd.bitlen > 1 && fd.translator != nullptr)
      display_bit = fd.shift + fd.bitlen - 1; // MSB anchor for enums
    else
      display_bit = fd.shift; // actual bit for single-bit or raw multi-bit fields
    out_lines.push_back({fd.group, line, fd.group, order_bit, display_bit, -1});
  };

  for (auto &f : base_fields)
  {
    // Determine class to gate DT_TYPE vs MS_CODE usage
    uint64 cls_bits = (flags & 0x00000600ULL);    // MS_CLS
    bool is_code_cls = cls_bits == 0x00000600ULL; // FF_CODE
    bool is_data_cls = cls_bits == 0x00000400ULL; // FF_DATA
    if (strcmp(f.label, "dtype") == 0 && !is_data_cls)
      continue; // show dtype only for data class
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
  out_lines.push_back({cb.grp, qstring().sprnt("%s=1", cb.nm), cb.grp, bitpos, bitpos, -1});
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
  lines.push_back(simpleline_t(bit_line.c_str()));

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

  // Render lines
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
    row += label;
    lines.push_back(simpleline_t(row.c_str()));
  }
}

void plugin_ctx_t::refresh_view()
{
  if (!widget)
    return;
  lines.qclear();

  ea_t ea = get_screen_ea();

  // Dissect flags visually, only showing set fields
  dissect_flags_verbose(get_full_flags(ea), lines);

  dump_flags(get_full_flags(ea), lines);

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
  switch (code)
  {
  case ui_screen_ea_changed:
    ///< cb: The "current address" changed
    ///< \param ea          (ea_t)
    ///< \param prev_ea     (ea_t)
    ///< \return void
    refresh_view();
    break;
  case ui_widget_invisible:
  {
    TWidget *w = va_arg(va, TWidget *);
    if (w == widget)
    {
      widget = nullptr;
      lines.qclear();
      unhook_event_listener(HT_UI, this);
    }
    break;
  }
  }
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
  widget = create_custom_viewer("Instruction Details", &s1, &s2, &s1, nullptr, &lines, nullptr, this);
  if (!widget)
    return false;

  hook_event_listener(HT_UI, this);
  display_widget(widget, WOPN_DP_TAB | WOPN_RESTORE);
  attach_action_to_popup(widget, nullptr, REFRESH_ACTION_NAME);

  refresh_view();
  return true;
}

static void dump_insn(const insn_t &insn, strvec_t &lines)
{
  auto add_line = [&lines](const char *nm, const qstring &ln)
  {
    qstring formatted_line;
    formatted_line.sprnt(" %s = %s", nm, ln.c_str());
    lines.push_back(simpleline_t(formatted_line.c_str()));
  };

  add_line("size", qstring().sprnt("%#x", insn.size));
  add_line("cs", qstring().sprnt("%#llx", insn.cs));
  add_line("ip", qstring().sprnt("%#llx", insn.ip));
  add_line("ea", qstring().sprnt("%#llx", insn.ea));

  add_line("itype", qstring().sprnt("%#x", static_cast<unsigned>(insn.itype)));

  qstring aux = qstring().sprnt("%#x", static_cast<unsigned>(insn.auxpref));
  add_line("auxpref", aux);

  if (insn.segpref != 0)
    add_line("segpref", qstring().sprnt("%#x", insn.segpref));
  if (insn.insnpref != 0)
    add_line("insnpref", qstring().sprnt("%#x", insn.insnpref));

  if (insn.flags == 0)
  {
    add_line("flags", "0");
  }
  else
  {
    qstring flags_desc;
    add_line("flags", qstring().sprnt("%x %s", static_cast<unsigned>(insn.flags), flags_desc.c_str()));
  }
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