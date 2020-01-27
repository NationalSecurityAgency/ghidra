/* ###
 * IP: LGPL 2.1
 * NOTE: See binutils/libiberty/COPYING.LIB
 */
/* Demangler for the Rust programming language
   Copyright (C) 2016-2019 Free Software Foundation, Inc.
   Written by David Tolnay (dtolnay@gmail.com).

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

#include <sys/types.h>
#include <string.h>
#include <stdio.h>

#ifdef HAVE_STRING_H
#include <string.h>
#else
extern size_t strlen(const char *s);
extern int strncmp(const char *s1, const char *s2, size_t n);
extern void *memset(void *s, int c, size_t n);
#endif

#include <demangle.h>
#include "libiberty.h"
#include "rust-demangle.h"


/* Mangled Rust symbols look like this:
     _$LT$std..sys..fd..FileDesc$u20$as$u20$core..ops..Drop$GT$::drop::hc68340e1baa4987a

   The original symbol is:
     <std::sys::fd::FileDesc as core::ops::Drop>::drop

   The last component of the path is a 64-bit hash in lowercase hex,
   prefixed with "h". Rust does not have a global namespace between
   crates, an illusion which Rust maintains by using the hash to
   distinguish things that would otherwise have the same symbol.

   Any path component not starting with a XID_Start character is
   prefixed with "_".

   The following escape sequences are used:

   ","  =>  $C$
   "@"  =>  $SP$
   "*"  =>  $BP$
   "&"  =>  $RF$
   "<"  =>  $LT$
   ">"  =>  $GT$
   "("  =>  $LP$
   ")"  =>  $RP$
   " "  =>  $u20$
   "\"" =>  $u22$
   "'"  =>  $u27$
   "+"  =>  $u2b$
   ";"  =>  $u3b$
   "["  =>  $u5b$
   "]"  =>  $u5d$
   "{"  =>  $u7b$
   "}"  =>  $u7d$
   "~"  =>  $u7e$

   A double ".." means "::" and a single "." means "-".

   The only characters allowed in the mangled symbol are a-zA-Z0-9 and _.:$  */

static const char *hash_prefix = "::h";
static const size_t hash_prefix_len = 3;
static const size_t hash_len = 16;

static int is_prefixed_hash (const char *start);
static int looks_like_rust (const char *sym, size_t len);
static int unescape (const char **in, char **out, const char *seq, char value);

/* INPUT: sym: symbol that has been through C++ (gnu v3) demangling

   This function looks for the following indicators:

   1. The hash must consist of "h" followed by 16 lowercase hex digits.

   2. As a sanity check, the hash must use between 5 and 15 of the 16
      possible hex digits. This is true of 99.9998% of hashes so once
      in your life you may see a false negative. The point is to
      notice path components that could be Rust hashes but are
      probably not, like "haaaaaaaaaaaaaaaa". In this case a false
      positive (non-Rust symbol has an important path component
      removed because it looks like a Rust hash) is worse than a false
      negative (the rare Rust symbol is not demangled) so this sets
      the balance in favor of false negatives.

   3. There must be no characters other than a-zA-Z0-9 and _.:$

   4. There must be no unrecognized $-sign sequences.

   5. There must be no sequence of three or more dots in a row ("...").  */

int
rust_is_mangled (const char *sym)
{
  size_t len, len_without_hash;

  if (!sym)
    return 0;

  len = strlen (sym);
  if (len <= hash_prefix_len + hash_len)
    /* Not long enough to contain "::h" + hash + something else */
    return 0;

  len_without_hash = len - (hash_prefix_len + hash_len);
  if (!is_prefixed_hash (sym + len_without_hash))
    return 0;

  return looks_like_rust (sym, len_without_hash);
}

/* A hash is the prefix "::h" followed by 16 lowercase hex digits. The
   hex digits must comprise between 5 and 15 (inclusive) distinct
   digits.  */

static int
is_prefixed_hash (const char *str)
{
  const char *end;
  char seen[16];
  size_t i;
  int count;

  if (strncmp (str, hash_prefix, hash_prefix_len))
    return 0;
  str += hash_prefix_len;

  memset (seen, 0, sizeof(seen));
  for (end = str + hash_len; str < end; str++)
    if (*str >= '0' && *str <= '9')
      seen[*str - '0'] = 1;
    else if (*str >= 'a' && *str <= 'f')
      seen[*str - 'a' + 10] = 1;
    else
      return 0;

  /* Count how many distinct digits seen */
  count = 0;
  for (i = 0; i < 16; i++)
    if (seen[i])
      count++;

  return count >= 5 && count <= 15;
}

static int
looks_like_rust (const char *str, size_t len)
{
  const char *end = str + len;

  while (str < end)
    switch (*str)
      {
      case '$':
	if (!strncmp (str, "$C$", 3))
	  str += 3;
	else if (!strncmp (str, "$SP$", 4)
		 || !strncmp (str, "$BP$", 4)
		 || !strncmp (str, "$RF$", 4)
		 || !strncmp (str, "$LT$", 4)
		 || !strncmp (str, "$GT$", 4)
		 || !strncmp (str, "$LP$", 4)
		 || !strncmp (str, "$RP$", 4))
	  str += 4;
	else if (!strncmp (str, "$u20$", 5)
		 || !strncmp (str, "$u22$", 5)
		 || !strncmp (str, "$u27$", 5)
		 || !strncmp (str, "$u2b$", 5)
		 || !strncmp (str, "$u3b$", 5)
		 || !strncmp (str, "$u5b$", 5)
		 || !strncmp (str, "$u5d$", 5)
		 || !strncmp (str, "$u7b$", 5)
		 || !strncmp (str, "$u7d$", 5)
		 || !strncmp (str, "$u7e$", 5))
	  str += 5;
	else
	  return 0;
	break;
      case '.':
	/* Do not allow three or more consecutive dots */
	if (!strncmp (str, "...", 3))
	  return 0;
	/* Fall through */
      case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
      case 'g': case 'h': case 'i': case 'j': case 'k': case 'l':
      case 'm': case 'n': case 'o': case 'p': case 'q': case 'r':
      case 's': case 't': case 'u': case 'v': case 'w': case 'x':
      case 'y': case 'z':
      case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
      case 'G': case 'H': case 'I': case 'J': case 'K': case 'L':
      case 'M': case 'N': case 'O': case 'P': case 'Q': case 'R':
      case 'S': case 'T': case 'U': case 'V': case 'W': case 'X':
      case 'Y': case 'Z':
      case '0': case '1': case '2': case '3': case '4': case '5':
      case '6': case '7': case '8': case '9':
      case '_':
      case ':':
	str++;
	break;
      default:
	return 0;
      }

  return 1;
}

/*
  INPUT: sym: symbol for which rust_is_mangled(sym) returned 1.

  The input is demangled in-place because the mangled name is always
  longer than the demangled one.  */

void
rust_demangle_sym (char *sym)
{
  const char *in;
  char *out;
  const char *end;

  if (!sym)
    return;

  in = sym;
  out = sym;
  end = sym + strlen (sym) - (hash_prefix_len + hash_len);

  while (in < end)
    switch (*in)
      {
      case '$':
	if (!(unescape (&in, &out, "$C$", ',')
	      || unescape (&in, &out, "$SP$", '@')
	      || unescape (&in, &out, "$BP$", '*')
	      || unescape (&in, &out, "$RF$", '&')
	      || unescape (&in, &out, "$LT$", '<')
	      || unescape (&in, &out, "$GT$", '>')
	      || unescape (&in, &out, "$LP$", '(')
	      || unescape (&in, &out, "$RP$", ')')
	      || unescape (&in, &out, "$u20$", ' ')
	      || unescape (&in, &out, "$u22$", '\"')
	      || unescape (&in, &out, "$u27$", '\'')
	      || unescape (&in, &out, "$u2b$", '+')
	      || unescape (&in, &out, "$u3b$", ';')
	      || unescape (&in, &out, "$u5b$", '[')
	      || unescape (&in, &out, "$u5d$", ']')
	      || unescape (&in, &out, "$u7b$", '{')
	      || unescape (&in, &out, "$u7d$", '}')
	      || unescape (&in, &out, "$u7e$", '~'))) {
	  /* unexpected escape sequence, not looks_like_rust. */
	  goto fail;
	}
	break;
      case '_':
	/* If this is the start of a path component and the next
	   character is an escape sequence, ignore the underscore. The
	   mangler inserts an underscore to make sure the path
	   component begins with a XID_Start character. */
	if ((in == sym || in[-1] == ':') && in[1] == '$')
	  in++;
	else
	  *out++ = *in++;
	break;
      case '.':
	if (in[1] == '.')
	  {
	    /* ".." becomes "::" */
	    *out++ = ':';
	    *out++ = ':';
	    in += 2;
	  }
	else
	  {
	    /* "." becomes "-" */
	    *out++ = '-';
	    in++;
	  }
	break;
      case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
      case 'g': case 'h': case 'i': case 'j': case 'k': case 'l':
      case 'm': case 'n': case 'o': case 'p': case 'q': case 'r':
      case 's': case 't': case 'u': case 'v': case 'w': case 'x':
      case 'y': case 'z':
      case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
      case 'G': case 'H': case 'I': case 'J': case 'K': case 'L':
      case 'M': case 'N': case 'O': case 'P': case 'Q': case 'R':
      case 'S': case 'T': case 'U': case 'V': case 'W': case 'X':
      case 'Y': case 'Z':
      case '0': case '1': case '2': case '3': case '4': case '5':
      case '6': case '7': case '8': case '9':
      case ':':
	*out++ = *in++;
	break;
      default:
	/* unexpected character in symbol, not looks_like_rust.  */
	goto fail;
      }
  goto done;

fail:
  *out++ = '?'; /* This is pretty lame, but it's hard to do better. */
done:
  *out = '\0';
}

static int
unescape (const char **in, char **out, const char *seq, char value)
{
  size_t len = strlen (seq);

  if (strncmp (*in, seq, len))
    return 0;

  **out = value;

  *in += len;
  *out += 1;

  return 1;
}
