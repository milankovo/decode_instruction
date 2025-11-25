#pragma once

#include <map>
#include <string>

#define TO_ENUM(X, comment) expanded_flag_t{X, #X, comment}

struct expanded_flag_t
{
  long long value;
  const char *name;
  const char *comment;
};

class FlagRegistry
{
public:
  static FlagRegistry &get()
  {
    static FlagRegistry instance;
    return instance;
  }

  void register_flag(const char *name, const char *desc)
  {
    if (name && desc)
    {
      descriptions[name] = desc;
    }
  }

  template <typename T>
  void register_array(const T &arr)
  {
    for (const auto &item : arr)
    {
      register_flag(item.name, item.comment);
    }
  }

  const char *get_description(const char *name)
  {
    auto it = descriptions.find(name);
    if (it != descriptions.end())
    {
      return it->second.c_str();
    }
    return nullptr;
  }

private:
  std::map<std::string, std::string> descriptions;
};

template <typename T>
struct AutoRegister
{
  AutoRegister(const T &arr)
  {
    FlagRegistry::get().register_array(arr);
  }
};

template <int N>
using flags_array_t = const std::array<expanded_flag_t, N>;
using flags_vector_t = const std::vector<expanded_flag_t>;

template <size_t N>
static const qstring explain_bits(int flag, flags_array_t<N> &flags)
{
  qstring flags_desc;
  auto initial_value = flag;
  auto first = true;
  for (const auto &entry : flags)
  {
    if ((entry.value & flag) == entry.value)
    {
      if (!first)
        flags_desc.append(" | ");
      flags_desc.append(entry.name);
      flag &= ~entry.value;
      first = false;
    }
  }
  if (flags_desc.empty())
    flags_desc.sprnt("%x", flag);
  else if (flag != 0)
    flags_desc.append(" | ").cat_sprnt("%x", flag);
  flags_desc.cat_sprnt(COMMENT( " // %#x"), initial_value);
  return flags_desc;
}


template <size_t N>
static const qstring explain_enum(int flag, flags_array_t<N> &flags)
{
    qstring flags_desc;
    auto initial_value = flag;

    for (const auto &entry : flags)
    {
        if ((entry.value == flag))
        {
            flags_desc.append(entry.name);
            break;
        }
    }
    if (flags_desc.empty())
        flags_desc.sprnt("%x", flag);
    flags_desc.cat_sprnt(COMMENT( " // %#x"), initial_value);
    return flags_desc;
}