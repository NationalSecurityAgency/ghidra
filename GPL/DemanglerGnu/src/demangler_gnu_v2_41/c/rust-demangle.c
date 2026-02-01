/* ###
 * IP: LGPL 2.1
 * NOTE: See binutils/libiberty/COPYING.LIB
 */
/* Demangler for the Rust programming language
   Copyright (C) 2016-2023 Free Software Foundation, Inc.
   Written by David Tolnay (dtolnay@gmail.com).
   Rewritten by Eduard-Mihai Burtescu (eddyb@lyken.rs) for v0 support.

This file is part of the libiberty library.
Libiberty is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public
License as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later version.

In addition to the permissions in the GNU Library General Public
License, the Free Software Foundation gives you unlimited permission
to link the compiled version of this file into combinations with other
programs, and to distribute those combinations without any restriction
coming from the use of this file.  (The Library Public License
restrictions do apply in other respects; for example, they cover
modification of the file, and distribution when not linked into a
combined executable.)

Libiberty is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with libiberty; see the file COPYING.LIB.
If not, see <http://www.gnu.org/licenses/>.  */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "safe-ctype.h"

#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_STRING_H
#include <string.h>
#else
extern size_t strlen(const char *s);
extern int strncmp(const char *s1, const char *s2, size_t n);
extern void *memset(void *s, int c, size_t n);
#endif

#include <demangle.h>
#include "libiberty.h"

struct rust_demangler
{
  const char *sym;
  size_t sym_len;

  void *callback_opaque;
  demangle_callbackref callback;

  /* Position of the next character to read from the symbol. */
  size_t next;

  /* Non-zero if any error occurred. */
  int errored;

  /* Non-zero if nothing should be printed. */
  int skipping_printing;

  /* Non-zero if printing should be verbose (e.g. include hashes). */
  int verbose;

  /* Rust mangling version, with legacy mangling being -1. */
  int version;

  /* Recursion depth.  */
  unsigned int recursion;
  /* Maximum number of times demangle_path may be called recursively.  */
#define RUST_MAX_RECURSION_COUNT  1024
#define RUST_NO_RECURSION_LIMIT   ((unsigned int) -1)

  uint64_t bound_lifetime_depth;
};

/* Parsing functions. */

static char
peek (const struct rust_demangler *rdm)
{
  if (rdm->next < rdm->sym_len)
    return rdm->sym[rdm->next];
  return 0;
}

static int
eat (struct rust_demangler *rdm, char c)
{
  if (peek (rdm) == c)
    {
      rdm->next++;
      return 1;
    }
  else
    return 0;
}

static char
next (struct rust_demangler *rdm)
{
  char c = peek (rdm);
  if (!c)
    rdm->errored = 1;
  else
    rdm->next++;
  return c;
}

static uint64_t
parse_integer_62 (struct rust_demangler *rdm)
{
  char c;
  uint64_t x;

  if (eat (rdm, '_'))
    return 0;

  x = 0;
  while (!eat (rdm, '_') && !rdm->errored)
    {
      c = next (rdm);
      x *= 62;
      if (ISDIGIT (c))
        x += c - '0';
      else if (ISLOWER (c))
        x += 10 + (c - 'a');
      else if (ISUPPER (c))
        x += 10 + 26 + (c - 'A');
      else
        {
          rdm->errored = 1;
          return 0;
        }
    }
  return x + 1;
}

static uint64_t
parse_opt_integer_62 (struct rust_demangler *rdm, char tag)
{
  if (!eat (rdm, tag))
    return 0;
  return 1 + parse_integer_62 (rdm);
}

static uint64_t
parse_disambiguator (struct rust_demangler *rdm)
{
  return parse_opt_integer_62 (rdm, 's');
}

static size_t
parse_hex_nibbles (struct rust_demangler *rdm, uint64_t *value)
{
  char c;
  size_t hex_len;

  hex_len = 0;
  *value = 0;

  while (!eat (rdm, '_'))
    {
      *value <<= 4;

      c = next (rdm);
      if (ISDIGIT (c))
        *value |= c - '0';
      else if (c >= 'a' && c <= 'f')
        *value |= 10 + (c - 'a');
      else
        {
          rdm->errored = 1;
          return 0;
        }
      hex_len++;
    }

  return hex_len;
}

struct rust_mangled_ident
{
  /* ASCII part of the identifier. */
  const char *ascii;
  size_t ascii_len;

  /* Punycode insertion codes for Unicode codepoints, if any. */
  const char *punycode;
  size_t punycode_len;
};

static struct rust_mangled_ident
parse_ident (struct rust_demangler *rdm)
{
  char c;
  size_t start, len;
  int is_punycode = 0;
  struct rust_mangled_ident ident;

  ident.ascii = NULL;
  ident.ascii_len = 0;
  ident.punycode = NULL;
  ident.punycode_len = 0;

  if (rdm->version != -1)
    is_punycode = eat (rdm, 'u');

  c = next (rdm);
  if (!ISDIGIT (c))
    {
      rdm->errored = 1;
      return ident;
    }
  len = c - '0';

  if (c != '0')
    while (ISDIGIT (peek (rdm)))
      len = len * 10 + (next (rdm) - '0');

  /* Skip past the optional `_` separator (v0). */
  if (rdm->version != -1)
    eat (rdm, '_');

  start = rdm->next;
  rdm->next += len;
  /* Check for overflows. */
  if ((start > rdm->next) || (rdm->next > rdm->sym_len))
    {
      rdm->errored = 1;
      return ident;
    }

  ident.ascii = rdm->sym + start;
  ident.ascii_len = len;

  if (is_punycode)
    {
      ident.punycode_len = 0;
      while (ident.ascii_len > 0)
        {
          ident.ascii_len--;

          /* The last '_' is a separator between ascii & punycode. */
          if (ident.ascii[ident.ascii_len] == '_')
            break;

          ident.punycode_len++;
        }
      if (!ident.punycode_len)
        {
          rdm->errored = 1;
          return ident;
        }
      ident.punycode = ident.ascii + (len - ident.punycode_len);
    }

  if (ident.ascii_len == 0)
    ident.ascii = NULL;

  return ident;
}

/* Printing functions. */

static void
print_str (struct rust_demangler *rdm, const char *data, size_t len)
{
  if (!rdm->errored && !rdm->skipping_printing)
    rdm->callback (data, len, rdm->callback_opaque);
}

#define PRINT(s) print_str (rdm, s, strlen (s))

static void
print_uint64 (struct rust_demangler *rdm, uint64_t x)
{
  char s[21];
  snprintf (s, 21, "%" PRIu64, x);
  PRINT (s);
}

static void
print_uint64_hex (struct rust_demangler *rdm, uint64_t x)
{
  char s[17];
  snprintf (s, 17, "%" PRIx64, x);
  PRINT (s);
}

/* Return a 0x0-0xf value if the char is 0-9a-f, and -1 otherwise. */
static int
decode_lower_hex_nibble (char nibble)
{
  if ('0' <= nibble && nibble <= '9')
    return nibble - '0';
  if ('a' <= nibble && nibble <= 'f')
    return 0xa + (nibble - 'a');
  return -1;
}

/* Return the unescaped character for a "$...$" escape, or 0 if invalid. */
static char
decode_legacy_escape (const char *e, size_t len, size_t *out_len)
{
  char c = 0;
  size_t escape_len = 0;
  int lo_nibble = -1, hi_nibble = -1;

  if (len < 3 || e[0] != '$')
    return 0;

  e++;
  len--;

  if (e[0] == 'C')
    {
      escape_len = 1;

      c = ',';
    }
  else if (len > 2)
    {
      escape_len = 2;

      if (e[0] == 'S' && e[1] == 'P')
        c = '@';
      else if (e[0] == 'B' && e[1] == 'P')
        c = '*';
      else if (e[0] == 'R' && e[1] == 'F')
        c = '&';
      else if (e[0] == 'L' && e[1] == 'T')
        c = '<';
      else if (e[0] == 'G' && e[1] == 'T')
        c = '>';
      else if (e[0] == 'L' && e[1] == 'P')
        c = '(';
      else if (e[0] == 'R' && e[1] == 'P')
        c = ')';
      else if (e[0] == 'u' && len > 3)
        {
          escape_len = 3;

          hi_nibble = decode_lower_hex_nibble (e[1]);
          if (hi_nibble < 0)
            return 0;
          lo_nibble = decode_lower_hex_nibble (e[2]);
          if (lo_nibble < 0)
            return 0;

          /* Only allow non-control ASCII characters. */
          if (hi_nibble > 7)
            return 0;
          c = (hi_nibble << 4) | lo_nibble;
          if (c < 0x20)
            return 0;
        }
    }

  if (!c || len <= escape_len || e[escape_len] != '$')
    return 0;

  *out_len = 2 + escape_len;
  return c;
}

static void
print_ident (struct rust_demangler *rdm, struct rust_mangled_ident ident)
{
  char unescaped;
  uint8_t *out, *p, d;
  size_t len, cap, punycode_pos, j;
  /* Punycode parameters and state. */
  uint32_t c;
  size_t base, t_min, t_max, skew, damp, bias, i;
  size_t delta, w, k, t;

  if (rdm->errored || rdm->skipping_printing)
    return;

  if (rdm->version == -1)
    {
      /* Ignore leading underscores preceding escape sequences.
         The mangler inserts an underscore to make sure the
         identifier begins with a XID_Start character. */
      if (ident.ascii_len >= 2 && ident.ascii[0] == '_'
          && ident.ascii[1] == '$')
        {
          ident.ascii++;
          ident.ascii_len--;
        }

      while (ident.ascii_len > 0)
        {
          /* Handle legacy escape sequences ("$...$", ".." or "."). */
          if (ident.ascii[0] == '$')
            {
              unescaped
                  = decode_legacy_escape (ident.ascii, ident.ascii_len, &len);
              if (unescaped)
                print_str (rdm, &unescaped, 1);
              else
                {
                  /* Unexpected escape sequence, print the rest verbatim. */
                  print_str (rdm, ident.ascii, ident.ascii_len);
                  return;
                }
            }
          else if (ident.ascii[0] == '.')
            {
              if (ident.ascii_len >= 2 && ident.ascii[1] == '.')
                {
                  /* ".." becomes "::" */
                  PRINT ("::");
                  len = 2;
                }
              else
                {
                  PRINT (".");
                  len = 1;
                }
            }
          else
            {
              /* Print everything before the next escape sequence, at once. */
              for (len = 0; len < ident.ascii_len; len++)
                if (ident.ascii[len] == '$' || ident.ascii[len] == '.')
                  break;

              print_str (rdm, ident.ascii, len);
            }

          ident.ascii += len;
          ident.ascii_len -= len;
        }

      return;
    }

  if (!ident.punycode)
    {
      print_str (rdm, ident.ascii, ident.ascii_len);
      return;
    }

  len = 0;
  cap = 4;
  while (cap < ident.ascii_len)
    {
      cap *= 2;
      /* Check for overflows. */
      if ((cap * 4) / 4 != cap)
        {
          rdm->errored = 1;
          return;
        }
    }

  /* Store the output codepoints as groups of 4 UTF-8 bytes. */
  out = (uint8_t *)malloc (cap * 4);
  if (!out)
    {
      rdm->errored = 1;
      return;
    }

  /* Populate initial output from ASCII fragment. */
  for (len = 0; len < ident.ascii_len; len++)
    {
      p = out + 4 * len;
      p[0] = 0;
      p[1] = 0;
      p[2] = 0;
      p[3] = ident.ascii[len];
    }

  /* Punycode parameters and initial state. */
  base = 36;
  t_min = 1;
  t_max = 26;
  skew = 38;
  damp = 700;
  bias = 72;
  i = 0;
  c = 0x80;

  punycode_pos = 0;
  while (punycode_pos < ident.punycode_len)
    {
      /* Read one delta value. */
      delta = 0;
      w = 1;
      k = 0;
      do
        {
          k += base;
          t = k < bias ? 0 : (k - bias);
          if (t < t_min)
            t = t_min;
          if (t > t_max)
            t = t_max;

          if (punycode_pos >= ident.punycode_len)
            goto cleanup;
          d = ident.punycode[punycode_pos++];

          if (ISLOWER (d))
            d = d - 'a';
          else if (ISDIGIT (d))
            d = 26 + (d - '0');
          else
            {
              rdm->errored = 1;
              goto cleanup;
            }

          delta += d * w;
          w *= base - t;
        }
      while (d >= t);

      /* Compute the new insert position and character. */
      len++;
      i += delta;
      c += i / len;
      i %= len;

      /* Ensure enough space is available. */
      if (cap < len)
        {
          cap *= 2;
          /* Check for overflows. */
          if ((cap * 4) / 4 != cap || cap < len)
            {
              rdm->errored = 1;
              goto cleanup;
            }
        }
      p = (uint8_t *)realloc (out, cap * 4);
      if (!p)
        {
          rdm->errored = 1;
          goto cleanup;
        }
      out = p;

      /* Move the characters after the insert position. */
      p = out + i * 4;
      memmove (p + 4, p, (len - i - 1) * 4);

      /* Insert the new character, as UTF-8 bytes. */
      p[0] = c >= 0x10000 ? 0xf0 | (c >> 18) : 0;
      p[1] = c >= 0x800 ? (c < 0x10000 ? 0xe0 : 0x80) | ((c >> 12) & 0x3f) : 0;
      p[2] = (c < 0x800 ? 0xc0 : 0x80) | ((c >> 6) & 0x3f);
      p[3] = 0x80 | (c & 0x3f);

      /* If there are no more deltas, decoding is complete. */
      if (punycode_pos == ident.punycode_len)
        break;

      i++;

      /* Perform bias adaptation. */
      delta /= damp;
      damp = 2;

      delta += delta / len;
      k = 0;
      while (delta > ((base - t_min) * t_max) / 2)
        {
          delta /= base - t_min;
          k += base;
        }
      bias = k + ((base - t_min + 1) * delta) / (delta + skew);
    }

  /* Remove all the 0 bytes to leave behind an UTF-8 string. */
  for (i = 0, j = 0; i < len * 4; i++)
    if (out[i] != 0)
      out[j++] = out[i];

  print_str (rdm, (const char *)out, j);

cleanup:
  free (out);
}

/* Print the lifetime according to the previously decoded index.
   An index of `0` always refers to `'_`, but starting with `1`,
   indices refer to late-bound lifetimes introduced by a binder. */
static void
print_lifetime_from_index (struct rust_demangler *rdm, uint64_t lt)
{
  char c;
  uint64_t depth;

  PRINT ("'");
  if (lt == 0)
    {
      PRINT ("_");
      return;
    }

  depth = rdm->bound_lifetime_depth - lt;
  /* Try to print lifetimes alphabetically first. */
  if (depth < 26)
    {
      c = 'a' + depth;
      print_str (rdm, &c, 1);
    }
  else
    {
      /* Use `'_123` after running out of letters. */
      PRINT ("_");
      print_uint64 (rdm, depth);
    }
}

/* Demangling functions. */

static void demangle_binder (struct rust_demangler *rdm);
static void demangle_path (struct rust_demangler *rdm, int in_value);
static void demangle_generic_arg (struct rust_demangler *rdm);
static void demangle_type (struct rust_demangler *rdm);
static int demangle_path_maybe_open_generics (struct rust_demangler *rdm);
static void demangle_dyn_trait (struct rust_demangler *rdm);
static void demangle_const (struct rust_demangler *rdm);
static void demangle_const_uint (struct rust_demangler *rdm);
static void demangle_const_int (struct rust_demangler *rdm);
static void demangle_const_bool (struct rust_demangler *rdm);
static void demangle_const_char (struct rust_demangler *rdm);

/* Optionally enter a binder ('G') for late-bound lifetimes,
   printing e.g. `for<'a, 'b> `, and make those lifetimes visible
   to the caller (via depth level, which the caller should reset). */
static void
demangle_binder (struct rust_demangler *rdm)
{
  uint64_t i, bound_lifetimes;

  if (rdm->errored)
    return;

  bound_lifetimes = parse_opt_integer_62 (rdm, 'G');
  if (bound_lifetimes > 0)
    {
      PRINT ("for<");
      for (i = 0; i < bound_lifetimes; i++)
        {
          if (i > 0)
            PRINT (", ");
          rdm->bound_lifetime_depth++;
          print_lifetime_from_index (rdm, 1);
        }
      PRINT ("> ");
    }
}

static void
demangle_path (struct rust_demangler *rdm, int in_value)
{
  char tag, ns;
  int was_skipping_printing;
  size_t i, backref, old_next;
  uint64_t dis;
  struct rust_mangled_ident name;

  if (rdm->errored)
    return;

  if (rdm->recursion != RUST_NO_RECURSION_LIMIT)
    {
      ++ rdm->recursion;
      if (rdm->recursion > RUST_MAX_RECURSION_COUNT)
	/* FIXME: There ought to be a way to report
	   that the recursion limit has been reached.  */
	goto fail_return;
    }

  switch (tag = next (rdm))
    {
    case 'C':
      dis = parse_disambiguator (rdm);
      name = parse_ident (rdm);

      print_ident (rdm, name);
      if (rdm->verbose)
        {
          PRINT ("[");
          print_uint64_hex (rdm, dis);
          PRINT ("]");
        }
      break;
    case 'N':
      ns = next (rdm);
      if (!ISLOWER (ns) && !ISUPPER (ns))
	goto fail_return;

      demangle_path (rdm, in_value);

      dis = parse_disambiguator (rdm);
      name = parse_ident (rdm);

      if (ISUPPER (ns))
        {
          /* Special namespaces, like closures and shims. */
          PRINT ("::{");
          switch (ns)
            {
            case 'C':
              PRINT ("closure");
              break;
            case 'S':
              PRINT ("shim");
              break;
            default:
              print_str (rdm, &ns, 1);
            }
          if (name.ascii || name.punycode)
            {
              PRINT (":");
              print_ident (rdm, name);
            }
          PRINT ("#");
          print_uint64 (rdm, dis);
          PRINT ("}");
        }
      else
        {
          /* Implementation-specific/unspecified namespaces. */

          if (name.ascii || name.punycode)
            {
              PRINT ("::");
              print_ident (rdm, name);
            }
        }
      break;
    case 'M':
    case 'X':
      /* Ignore the `impl`'s own path.*/
      parse_disambiguator (rdm);
      was_skipping_printing = rdm->skipping_printing;
      rdm->skipping_printing = 1;
      demangle_path (rdm, in_value);
      rdm->skipping_printing = was_skipping_printing;
      /* fallthrough */
    case 'Y':
      PRINT ("<");
      demangle_type (rdm);
      if (tag != 'M')
        {
          PRINT (" as ");
          demangle_path (rdm, 0);
        }
      PRINT (">");
      break;
    case 'I':
      demangle_path (rdm, in_value);
      if (in_value)
        PRINT ("::");
      PRINT ("<");
      for (i = 0; !rdm->errored && !eat (rdm, 'E'); i++)
        {
          if (i > 0)
            PRINT (", ");
          demangle_generic_arg (rdm);
        }
      PRINT (">");
      break;
    case 'B':
      backref = parse_integer_62 (rdm);
      if (!rdm->skipping_printing)
        {
          old_next = rdm->next;
          rdm->next = backref;
          demangle_path (rdm, in_value);
          rdm->next = old_next;
        }
      break;
    default:
      goto fail_return;
    }
  goto pass_return;

 fail_return:
  rdm->errored = 1;
 pass_return:
  if (rdm->recursion != RUST_NO_RECURSION_LIMIT)
    -- rdm->recursion;
}

static void
demangle_generic_arg (struct rust_demangler *rdm)
{
  uint64_t lt;
  if (eat (rdm, 'L'))
    {
      lt = parse_integer_62 (rdm);
      print_lifetime_from_index (rdm, lt);
    }
  else if (eat (rdm, 'K'))
    demangle_const (rdm);
  else
    demangle_type (rdm);
}

static const char *
basic_type (char tag)
{
  switch (tag)
    {
    case 'b':
      return "bool";
    case 'c':
      return "char";
    case 'e':
      return "str";
    case 'u':
      return "()";
    case 'a':
      return "i8";
    case 's':
      return "i16";
    case 'l':
      return "i32";
    case 'x':
      return "i64";
    case 'n':
      return "i128";
    case 'i':
      return "isize";
    case 'h':
      return "u8";
    case 't':
      return "u16";
    case 'm':
      return "u32";
    case 'y':
      return "u64";
    case 'o':
      return "u128";
    case 'j':
      return "usize";
    case 'f':
      return "f32";
    case 'd':
      return "f64";
    case 'z':
      return "!";
    case 'p':
      return "_";
    case 'v':
      return "...";

    default:
      return NULL;
    }
}

static void
demangle_type (struct rust_demangler *rdm)
{
  char tag;
  size_t i, old_next, backref;
  uint64_t lt, old_bound_lifetime_depth;
  const char *basic;
  struct rust_mangled_ident abi;

  if (rdm->errored)
    return;

  tag = next (rdm);

  basic = basic_type (tag);
  if (basic)
    {
      PRINT (basic);
      return;
    }

   if (rdm->recursion != RUST_NO_RECURSION_LIMIT)
    {
      ++ rdm->recursion;
      if (rdm->recursion > RUST_MAX_RECURSION_COUNT)
	/* FIXME: There ought to be a way to report
	   that the recursion limit has been reached.  */
	{
	  rdm->errored = 1;
	  -- rdm->recursion;
	  return;
	}
    }

  switch (tag)
    {
    case 'R':
    case 'Q':
      PRINT ("&");
      if (eat (rdm, 'L'))
        {
          lt = parse_integer_62 (rdm);
          if (lt)
            {
              print_lifetime_from_index (rdm, lt);
              PRINT (" ");
            }
        }
      if (tag != 'R')
        PRINT ("mut ");
      demangle_type (rdm);
      break;
    case 'P':
    case 'O':
      PRINT ("*");
      if (tag != 'P')
        PRINT ("mut ");
      else
        PRINT ("const ");
      demangle_type (rdm);
      break;
    case 'A':
    case 'S':
      PRINT ("[");
      demangle_type (rdm);
      if (tag == 'A')
        {
          PRINT ("; ");
          demangle_const (rdm);
        }
      PRINT ("]");
      break;
    case 'T':
      PRINT ("(");
      for (i = 0; !rdm->errored && !eat (rdm, 'E'); i++)
        {
          if (i > 0)
            PRINT (", ");
          demangle_type (rdm);
        }
      if (i == 1)
        PRINT (",");
      PRINT (")");
      break;
    case 'F':
      old_bound_lifetime_depth = rdm->bound_lifetime_depth;
      demangle_binder (rdm);

      if (eat (rdm, 'U'))
        PRINT ("unsafe ");

      if (eat (rdm, 'K'))
        {
          if (eat (rdm, 'C'))
            {
              abi.ascii = "C";
              abi.ascii_len = 1;
            }
          else
            {
              abi = parse_ident (rdm);
              if (!abi.ascii || abi.punycode)
                {
                  rdm->errored = 1;
                  goto restore;
                }
            }

          PRINT ("extern \"");

          /* If the ABI had any `-`, they were replaced with `_`,
             so the parts between `_` have to be re-joined with `-`. */
          for (i = 0; i < abi.ascii_len; i++)
            {
              if (abi.ascii[i] == '_')
                {
                  print_str (rdm, abi.ascii, i);
                  PRINT ("-");
                  abi.ascii += i + 1;
                  abi.ascii_len -= i + 1;
                  i = 0;
                }
            }
          print_str (rdm, abi.ascii, abi.ascii_len);

          PRINT ("\" ");
        }

      PRINT ("fn(");
      for (i = 0; !rdm->errored && !eat (rdm, 'E'); i++)
        {
          if (i > 0)
            PRINT (", ");
          demangle_type (rdm);
        }
      PRINT (")");

      if (eat (rdm, 'u'))
        {
          /* Skip printing the return type if it's 'u', i.e. `()`. */
        }
      else
        {
          PRINT (" -> ");
          demangle_type (rdm);
        }

    /* Restore `bound_lifetime_depth` to outside the binder. */
    restore:
      rdm->bound_lifetime_depth = old_bound_lifetime_depth;
      break;
    case 'D':
      PRINT ("dyn ");

      old_bound_lifetime_depth = rdm->bound_lifetime_depth;
      demangle_binder (rdm);

      for (i = 0; !rdm->errored && !eat (rdm, 'E'); i++)
        {
          if (i > 0)
            PRINT (" + ");
          demangle_dyn_trait (rdm);
        }

      /* Restore `bound_lifetime_depth` to outside the binder. */
      rdm->bound_lifetime_depth = old_bound_lifetime_depth;

      if (!eat (rdm, 'L'))
        {
          rdm->errored = 1;
          return;
        }
      lt = parse_integer_62 (rdm);
      if (lt)
        {
          PRINT (" + ");
          print_lifetime_from_index (rdm, lt);
        }
      break;
    case 'B':
      backref = parse_integer_62 (rdm);
      if (!rdm->skipping_printing)
        {
          old_next = rdm->next;
          rdm->next = backref;
          demangle_type (rdm);
          rdm->next = old_next;
        }
      break;
    default:
      /* Go back to the tag, so `demangle_path` also sees it. */
      rdm->next--;
      demangle_path (rdm, 0);
    }

  if (rdm->recursion != RUST_NO_RECURSION_LIMIT)
    -- rdm->recursion;
}

/* A trait in a trait object may have some "existential projections"
   (i.e. associated type bindings) after it, which should be printed
   in the `<...>` of the trait, e.g. `dyn Trait<T, U, Assoc=X>`.
   To this end, this method will keep the `<...>` of an 'I' path
   open, by omitting the `>`, and return `Ok(true)` in that case. */
static int
demangle_path_maybe_open_generics (struct rust_demangler *rdm)
{
  int open;
  size_t i, old_next, backref;

  open = 0;

  if (rdm->errored)
    return open;

  if (rdm->recursion != RUST_NO_RECURSION_LIMIT)
    {
      ++ rdm->recursion;
      if (rdm->recursion > RUST_MAX_RECURSION_COUNT)
	{
	  /* FIXME: There ought to be a way to report
	     that the recursion limit has been reached.  */
	  rdm->errored = 1;
	  goto end_of_func;
	}
    }

  if (eat (rdm, 'B'))
    {
      backref = parse_integer_62 (rdm);
      if (!rdm->skipping_printing)
        {
          old_next = rdm->next;
          rdm->next = backref;
          open = demangle_path_maybe_open_generics (rdm);
          rdm->next = old_next;
        }
    }
  else if (eat (rdm, 'I'))
    {
      demangle_path (rdm, 0);
      PRINT ("<");
      open = 1;
      for (i = 0; !rdm->errored && !eat (rdm, 'E'); i++)
        {
          if (i > 0)
            PRINT (", ");
          demangle_generic_arg (rdm);
        }
    }
  else
    demangle_path (rdm, 0);

 end_of_func:
  if (rdm->recursion != RUST_NO_RECURSION_LIMIT)
    -- rdm->recursion;

  return open;
}

static void
demangle_dyn_trait (struct rust_demangler *rdm)
{
  int open;
  struct rust_mangled_ident name;

  if (rdm->errored)
    return;

  open = demangle_path_maybe_open_generics (rdm);

  while (eat (rdm, 'p'))
    {
      if (!open)
        PRINT ("<");
      else
        PRINT (", ");
      open = 1;

      name = parse_ident (rdm);
      print_ident (rdm, name);
      PRINT (" = ");
      demangle_type (rdm);
    }

  if (open)
    PRINT (">");
}

static void
demangle_const (struct rust_demangler *rdm)
{
  char ty_tag;
  size_t old_next, backref;

  if (rdm->errored)
    return;

  if (rdm->recursion != RUST_NO_RECURSION_LIMIT)
    {
      ++ rdm->recursion;
      if (rdm->recursion > RUST_MAX_RECURSION_COUNT)
	/* FIXME: There ought to be a way to report
	   that the recursion limit has been reached.  */
	goto fail_return;
    }

  if (eat (rdm, 'B'))
    {
      backref = parse_integer_62 (rdm);
      if (!rdm->skipping_printing)
        {
          old_next = rdm->next;
          rdm->next = backref;
          demangle_const (rdm);
          rdm->next = old_next;
        }
      goto pass_return;
    }

  ty_tag = next (rdm);
  switch (ty_tag)
    {
    /* Placeholder. */
    case 'p':
      PRINT ("_");
      goto pass_return;

    /* Unsigned integer types. */
    case 'h':
    case 't':
    case 'm':
    case 'y':
    case 'o':
    case 'j':
      demangle_const_uint (rdm);
      break;

    /* Signed integer types. */
    case 'a':
    case 's':
    case 'l':
    case 'x':
    case 'n':
    case 'i':
      demangle_const_int (rdm);
      break;

    /* Boolean. */
    case 'b':
      demangle_const_bool (rdm);
      break;

    /* Character. */
    case 'c':
      demangle_const_char (rdm);
      break;

    default:
      goto fail_return;
    }

  if (!rdm->errored && rdm->verbose)
    {
      PRINT (": ");
      PRINT (basic_type (ty_tag));
    }
  goto pass_return;

 fail_return:
  rdm->errored = 1;
 pass_return:
  if (rdm->recursion != RUST_NO_RECURSION_LIMIT)
    -- rdm->recursion;
}

static void
demangle_const_uint (struct rust_demangler *rdm)
{
  size_t hex_len;
  uint64_t value;

  if (rdm->errored)
    return;

  hex_len = parse_hex_nibbles (rdm, &value);

  if (hex_len > 16)
    {
      /* Print anything that doesn't fit in `uint64_t` verbatim. */
      PRINT ("0x");
      print_str (rdm, rdm->sym + (rdm->next - hex_len), hex_len);
    }
  else if (hex_len > 0)
    print_uint64 (rdm, value);
  else
    rdm->errored = 1;
}

static void
demangle_const_int (struct rust_demangler *rdm)
{
  if (eat (rdm, 'n'))
    PRINT ("-");
  demangle_const_uint (rdm);
}

static void
demangle_const_bool (struct rust_demangler *rdm)
{
  uint64_t value;

  if (parse_hex_nibbles (rdm, &value) != 1)
    {
      rdm->errored = 1;
      return;
    }

  if (value == 0)
    PRINT ("false");
  else if (value == 1)
    PRINT ("true");
  else
    rdm->errored = 1;
}

static void
demangle_const_char (struct rust_demangler *rdm)
{
  size_t hex_len;
  uint64_t value;

  hex_len = parse_hex_nibbles (rdm, &value);

  if (hex_len == 0 || hex_len > 8)
    {
      rdm->errored = 1;
      return;
    }

  /* Match Rust's character "debug" output as best as we can. */
  PRINT ("'");
  if (value == '\t')
    PRINT ("\\t");
  else if (value == '\r')
    PRINT ("\\r");
  else if (value == '\n')
    PRINT ("\\n");
  else if (value > ' ' && value < '~')
    {
      /* Rust also considers many non-ASCII codepoints to be printable, but
	 that logic is not easily ported to C. */
      char c = value;
      print_str (rdm, &c, 1);
    }
  else
    {
      PRINT ("\\u{");
      print_uint64_hex (rdm, value);
      PRINT ("}");
    }
  PRINT ("'");
}

/* A legacy hash is the prefix "h" followed by 16 lowercase hex digits.
   The hex digits must contain at least 5 distinct digits. */
static int
is_legacy_prefixed_hash (struct rust_mangled_ident ident)
{
  uint16_t seen;
  int nibble;
  size_t i, count;

  if (ident.ascii_len != 17 || ident.ascii[0] != 'h')
    return 0;

  seen = 0;
  for (i = 0; i < 16; i++)
    {
      nibble = decode_lower_hex_nibble (ident.ascii[1 + i]);
      if (nibble < 0)
        return 0;
      seen |= (uint16_t)1 << nibble;
    }

  /* Count how many distinct digits were seen. */
  count = 0;
  while (seen)
    {
      if (seen & 1)
        count++;
      seen >>= 1;
    }

  return count >= 5;
}

int
rust_demangle_callback (const char *mangled, int options,
                        demangle_callbackref callback, void *opaque)
{
  const char *p;
  struct rust_demangler rdm;
  struct rust_mangled_ident ident;

  rdm.sym = mangled;
  rdm.sym_len = 0;

  rdm.callback_opaque = opaque;
  rdm.callback = callback;

  rdm.next = 0;
  rdm.errored = 0;
  rdm.skipping_printing = 0;
  rdm.verbose = (options & DMGL_VERBOSE) != 0;
  rdm.version = 0;
  rdm.recursion = (options & DMGL_NO_RECURSE_LIMIT) ? RUST_NO_RECURSION_LIMIT : 0;
  rdm.bound_lifetime_depth = 0;

  /* Rust symbols always start with _R (v0) or _ZN (legacy). */
  if (rdm.sym[0] == '_' && rdm.sym[1] == 'R')
    rdm.sym += 2;
  else if (rdm.sym[0] == '_' && rdm.sym[1] == 'Z' && rdm.sym[2] == 'N')
    {
      rdm.sym += 3;
      rdm.version = -1;
    }
  else
    return 0;

  /* Paths (v0) always start with uppercase characters. */
  if (rdm.version != -1 && !ISUPPER (rdm.sym[0]))
    return 0;

  /* Rust symbols (v0) use only [_0-9a-zA-Z] characters. */
  for (p = rdm.sym; *p; p++)
    {
      /* Rust v0 symbols can have '.' suffixes, ignore those.  */
      if (rdm.version == 0 && *p == '.')
        break;

      rdm.sym_len++;

      if (*p == '_' || ISALNUM (*p))
        continue;

      /* Legacy Rust symbols can also contain [.:$] characters.
         Or @ in the .suffix (which will be skipped, see below). */
      if (rdm.version == -1 && (*p == '$' || *p == '.' || *p == ':'
                                || *p == '@'))
        continue;

      return 0;
    }

  /* Legacy Rust symbols need to be handled separately. */
  if (rdm.version == -1)
    {
      /* Legacy Rust symbols always end with E.  But can be followed by a
         .suffix (which we want to ignore).  */
      int dot_suffix = 1;
      while (rdm.sym_len > 0 &&
             !(dot_suffix && rdm.sym[rdm.sym_len - 1] == 'E'))
        {
          dot_suffix = rdm.sym[rdm.sym_len - 1] == '.';
          rdm.sym_len--;
        }

      if (!(rdm.sym_len > 0 && rdm.sym[rdm.sym_len - 1] == 'E'))
        return 0;
      rdm.sym_len--;

      /* Legacy Rust symbols also always end with a path segment
         that encodes a 16 hex digit hash, i.e. '17h[a-f0-9]{16}'.
         This early check, before any parse_ident calls, should
         quickly filter out most C++ symbols unrelated to Rust. */
      if (!(rdm.sym_len > 19
            && !memcmp (&rdm.sym[rdm.sym_len - 19], "17h", 3)))
        return 0;

      do
        {
          ident = parse_ident (&rdm);
          if (rdm.errored || !ident.ascii)
            return 0;
        }
      while (rdm.next < rdm.sym_len);

      /* The last path segment should be the hash. */
      if (!is_legacy_prefixed_hash (ident))
        return 0;

      /* Reset the state for a second pass, to print the symbol. */
      rdm.next = 0;
      if (!rdm.verbose && rdm.sym_len > 19)
        {
          /* Hide the last segment, containing the hash, if not verbose. */
          rdm.sym_len -= 19;
        }

      do
        {
          if (rdm.next > 0)
            print_str (&rdm, "::", 2);

          ident = parse_ident (&rdm);
          print_ident (&rdm, ident);
        }
      while (rdm.next < rdm.sym_len);
    }
  else
    {
      demangle_path (&rdm, 1);

      /* Skip instantiating crate. */
      if (!rdm.errored && rdm.next < rdm.sym_len)
        {
          rdm.skipping_printing = 1;
          demangle_path (&rdm, 0);
        }

      /* It's an error to not reach the end. */
      rdm.errored |= rdm.next != rdm.sym_len;
    }

  return !rdm.errored;
}

/* Growable string buffers. */
struct str_buf
{
  char *ptr;
  size_t len;
  size_t cap;
  int errored;
};

static void
str_buf_reserve (struct str_buf *buf, size_t extra)
{
  size_t available, min_new_cap, new_cap;
  char *new_ptr;

  /* Allocation failed before. */
  if (buf->errored)
    return;

  available = buf->cap - buf->len;

  if (extra <= available)
    return;

  min_new_cap = buf->cap + (extra - available);

  /* Check for overflows. */
  if (min_new_cap < buf->cap)
    {
      buf->errored = 1;
      return;
    }

  new_cap = buf->cap;

  if (new_cap == 0)
    new_cap = 4;

  /* Double capacity until sufficiently large. */
  while (new_cap < min_new_cap)
    {
      new_cap *= 2;

      /* Check for overflows. */
      if (new_cap < buf->cap)
        {
          buf->errored = 1;
          return;
        }
    }

  new_ptr = (char *)realloc (buf->ptr, new_cap);
  if (new_ptr == NULL)
    {
      free (buf->ptr);
      buf->ptr = NULL;
      buf->len = 0;
      buf->cap = 0;
      buf->errored = 1;
    }
  else
    {
      buf->ptr = new_ptr;
      buf->cap = new_cap;
    }
}

static void
str_buf_append (struct str_buf *buf, const char *data, size_t len)
{
  str_buf_reserve (buf, len);
  if (buf->errored)
    return;

  memcpy (buf->ptr + buf->len, data, len);
  buf->len += len;
}

static void
str_buf_demangle_callback (const char *data, size_t len, void *opaque)
{
  str_buf_append ((struct str_buf *)opaque, data, len);
}

char *
rust_demangle (const char *mangled, int options)
{
  struct str_buf out;
  int success;

  out.ptr = NULL;
  out.len = 0;
  out.cap = 0;
  out.errored = 0;

  success = rust_demangle_callback (mangled, options,
                                    str_buf_demangle_callback, &out);

  if (!success)
    {
      free (out.ptr);
      return NULL;
    }

  str_buf_append (&out, "\0", 1);
  return out.ptr;
}
