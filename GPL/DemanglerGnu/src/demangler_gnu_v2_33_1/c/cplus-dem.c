/* ###
 * IP: LGPL 2.1
 * NOTE: See binutils/libiberty/COPYING.LIB
 */
/* Demangler for GNU C++
   Copyright (C) 1989-2019 Free Software Foundation, Inc.
   Written by James Clark (jjc@jclark.uucp)
   Rewritten by Fred Fish (fnf@cygnus.com) for ARM and Lucid demangling
   Modified by Satish Pai (pai@apollo.hp.com) for HP demangling

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
License along with libiberty; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 51 Franklin Street - Fifth Floor,
Boston, MA 02110-1301, USA.  */

/* This file lives in both GCC and libiberty.  When making changes, please
   try not to break either.  */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "safe-ctype.h"

#include <string.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
void * malloc ();
void * realloc ();
#endif

#include <demangle.h>
#undef CURRENT_DEMANGLING_STYLE
#define CURRENT_DEMANGLING_STYLE options

#include "libiberty.h"
#include "rust-demangle.h"

enum demangling_styles current_demangling_style = auto_demangling;

const struct demangler_engine libiberty_demanglers[] =
{
  {
    NO_DEMANGLING_STYLE_STRING,
    no_demangling,
    "Demangling disabled"
  }
  ,
  {
    AUTO_DEMANGLING_STYLE_STRING,
      auto_demangling,
      "Automatic selection based on executable"
  }
  ,
  {
    GNU_V3_DEMANGLING_STYLE_STRING,
    gnu_v3_demangling,
    "GNU (g++) V3 (Itanium C++ ABI) style demangling"
  }
  ,
  {
    JAVA_DEMANGLING_STYLE_STRING,
    java_demangling,
    "Java style demangling"
  }
  ,
  {
    GNAT_DEMANGLING_STYLE_STRING,
    gnat_demangling,
    "GNAT style demangling"
  }
  ,
  {
    DLANG_DEMANGLING_STYLE_STRING,
    dlang_demangling,
    "DLANG style demangling"
  }
  ,
  {
    RUST_DEMANGLING_STYLE_STRING,
    rust_demangling,
    "Rust style demangling"
  }
  ,
  {
    NULL, unknown_demangling, NULL
  }
};

/* Add a routine to set the demangling style to be sure it is valid and
   allow for any demangler initialization that maybe necessary. */

enum demangling_styles
cplus_demangle_set_style (enum demangling_styles style)
{
  const struct demangler_engine *demangler = libiberty_demanglers; 

  for (; demangler->demangling_style != unknown_demangling; ++demangler)
    if (style == demangler->demangling_style)
      {
	current_demangling_style = style;
	return current_demangling_style;
      }

  return unknown_demangling;
}

/* Do string name to style translation */

enum demangling_styles
cplus_demangle_name_to_style (const char *name)
{
  const struct demangler_engine *demangler = libiberty_demanglers; 

  for (; demangler->demangling_style != unknown_demangling; ++demangler)
    if (strcmp (name, demangler->demangling_style_name) == 0)
      return demangler->demangling_style;

  return unknown_demangling;
}

/* char *cplus_demangle (const char *mangled, int options)

   If MANGLED is a mangled function name produced by GNU C++, then
   a pointer to a @code{malloc}ed string giving a C++ representation
   of the name will be returned; otherwise NULL will be returned.
   It is the caller's responsibility to free the string which
   is returned.

   Note that any leading underscores, or other such characters prepended by
   the compilation system, are presumed to have already been stripped from
   MANGLED.  */

char *
cplus_demangle (const char *mangled, int options)
{
  char *ret;

  if (current_demangling_style == no_demangling)
    return xstrdup (mangled);

  if ((options & DMGL_STYLE_MASK) == 0)
    options |= (int) current_demangling_style & DMGL_STYLE_MASK;

  /* The V3 ABI demangling is implemented elsewhere.  */
  if (GNU_V3_DEMANGLING || RUST_DEMANGLING || AUTO_DEMANGLING)
    {
      ret = cplus_demangle_v3 (mangled, options);
      if (GNU_V3_DEMANGLING)
	return ret;

      if (ret)
	{
	  /* Rust symbols are GNU_V3 mangled plus some extra subtitutions.
	     The subtitutions are always smaller, so do in place changes.  */
	  if (rust_is_mangled (ret))
	    rust_demangle_sym (ret);
	  else if (RUST_DEMANGLING)
	    {
	      free (ret);
	      ret = NULL;
	    }
	}

      if (ret || RUST_DEMANGLING)
	return ret;
    }

  if (JAVA_DEMANGLING)
    {
      ret = java_demangle_v3 (mangled);
      if (ret)
        return ret;
    }

  if (GNAT_DEMANGLING)
    return ada_demangle (mangled, options);

  if (DLANG_DEMANGLING)
    {
      ret = dlang_demangle (mangled, options);
      if (ret)
	return ret;
    }

  return (ret);
}

char *
rust_demangle (const char *mangled, int options)
{
  /* Rust symbols are GNU_V3 mangled plus some extra subtitutions.  */
  char *ret = cplus_demangle_v3 (mangled, options);

  /* The Rust subtitutions are always smaller, so do in place changes.  */
  if (ret != NULL)
    {
      if (rust_is_mangled (ret))
	rust_demangle_sym (ret);
      else
	{
	  free (ret);
	  ret = NULL;
	}
    }

  return ret;
}

/* Demangle ada names.  The encoding is documented in gcc/ada/exp_dbug.ads.  */

char *
ada_demangle (const char *mangled, int option ATTRIBUTE_UNUSED)
{
  int len0;
  const char* p;
  char *d;
  char *demangled = NULL;
  
  /* Discard leading _ada_, which is used for library level subprograms.  */
  if (strncmp (mangled, "_ada_", 5) == 0)
    mangled += 5;

  /* All ada unit names are lower-case.  */
  if (!ISLOWER (mangled[0]))
    goto unknown;

  /* Most of the demangling will trivially remove chars.  Operator names
     may add one char but because they are always preceeded by '__' which is
     replaced by '.', they eventually never expand the size.
     A few special names such as '___elabs' add a few chars (at most 7), but
     they occur only once.  */
  len0 = strlen (mangled) + 7 + 1;
  demangled = XNEWVEC (char, len0);
  
  d = demangled;
  p = mangled;
  while (1)
    {
      /* An entity names is expected.  */
      if (ISLOWER (*p))
        {
          /* An identifier, which is always lower case.  */
          do
            *d++ = *p++;
          while (ISLOWER(*p) || ISDIGIT (*p)
                 || (p[0] == '_' && (ISLOWER (p[1]) || ISDIGIT (p[1]))));
        }
      else if (p[0] == 'O')
        {
          /* An operator name.  */
          static const char * const operators[][2] =
            {{"Oabs", "abs"},  {"Oand", "and"},    {"Omod", "mod"},
             {"Onot", "not"},  {"Oor", "or"},      {"Orem", "rem"},
             {"Oxor", "xor"},  {"Oeq", "="},       {"One", "/="},
             {"Olt", "<"},     {"Ole", "<="},      {"Ogt", ">"},
             {"Oge", ">="},    {"Oadd", "+"},      {"Osubtract", "-"},
             {"Oconcat", "&"}, {"Omultiply", "*"}, {"Odivide", "/"},
             {"Oexpon", "**"}, {NULL, NULL}};
          int k;

          for (k = 0; operators[k][0] != NULL; k++)
            {
              size_t slen = strlen (operators[k][0]);
              if (strncmp (p, operators[k][0], slen) == 0)
                {
                  p += slen;
                  slen = strlen (operators[k][1]);
                  *d++ = '"';
                  memcpy (d, operators[k][1], slen);
                  d += slen;
                  *d++ = '"';
                  break;
                }
            }
          /* Operator not found.  */
          if (operators[k][0] == NULL)
            goto unknown;
        }
      else
        {
          /* Not a GNAT encoding.  */
          goto unknown;
        }

      /* The name can be directly followed by some uppercase letters.  */
      if (p[0] == 'T' && p[1] == 'K')
        {
          /* Task stuff.  */
          if (p[2] == 'B' && p[3] == 0)
            {
              /* Subprogram for task body.  */
              break;
            }
          else if (p[2] == '_' && p[3] == '_')
            {
              /* Inner declarations in a task.  */
              p += 4;
              *d++ = '.';
              continue;
            }
          else
            goto unknown;
        }
      if (p[0] == 'E' && p[1] == 0)
        {
          /* Exception name.  */
          goto unknown;
        }
      if ((p[0] == 'P' || p[0] == 'N') && p[1] == 0)
        {
          /* Protected type subprogram.  */
          break;
        }
      if ((*p == 'N' || *p == 'S') && p[1] == 0)
        {
          /* Enumerated type name table.  */
          goto unknown;
        }
      if (p[0] == 'X')
        {
          /* Body nested.  */
          p++;
          while (p[0] == 'n' || p[0] == 'b')
            p++;
        }
      if (p[0] == 'S' && p[1] != 0 && (p[2] == '_' || p[2] == 0))
        {
          /* Stream operations.  */
          const char *name;
          switch (p[1])
            {
            case 'R':
              name = "'Read";
              break;
            case 'W':
              name = "'Write";
              break;
            case 'I':
              name = "'Input";
              break;
            case 'O':
              name = "'Output";
              break;
            default:
              goto unknown;
            }
          p += 2;
          strcpy (d, name);
          d += strlen (name);
        }
      else if (p[0] == 'D')
        {
          /* Controlled type operation.  */
          const char *name;
          switch (p[1])
            {
            case 'F':
              name = ".Finalize";
              break;
            case 'A':
              name = ".Adjust";
              break;
            default:
              goto unknown;
            }
          strcpy (d, name);
          d += strlen (name);
          break;
        }

      if (p[0] == '_')
        {
          /* Separator.  */
          if (p[1] == '_')
            {
              /* Standard separator.  Handled first.  */
              p += 2;

              if (ISDIGIT (*p))
                {
                  /* Overloading number.  */
                  do
                    p++;
                  while (ISDIGIT (*p) || (p[0] == '_' && ISDIGIT (p[1])));
                  if (*p == 'X')
                    {
                      p++;
                      while (p[0] == 'n' || p[0] == 'b')
                        p++;
                    }
                }
              else if (p[0] == '_' && p[1] != '_')
                {
                  /* Special names.  */
                  static const char * const special[][2] = {
                    { "_elabb", "'Elab_Body" },
                    { "_elabs", "'Elab_Spec" },
                    { "_size", "'Size" },
                    { "_alignment", "'Alignment" },
                    { "_assign", ".\":=\"" },
                    { NULL, NULL }
                  };
                  int k;

                  for (k = 0; special[k][0] != NULL; k++)
                    {
                      size_t slen = strlen (special[k][0]);
                      if (strncmp (p, special[k][0], slen) == 0)
                        {
                          p += slen;
                          slen = strlen (special[k][1]);
                          memcpy (d, special[k][1], slen);
                          d += slen;
                          break;
                        }
                    }
                  if (special[k][0] != NULL)
                    break;
                  else
                    goto unknown;
                }
              else
                {
                  *d++ = '.';
                  continue;
                }
            }
          else if (p[1] == 'B' || p[1] == 'E')
            {
              /* Entry Body or barrier Evaluation.  */
              p += 2;
              while (ISDIGIT (*p))
                p++;
              if (p[0] == 's' && p[1] == 0)
                break;
              else
                goto unknown;
            }
          else
            goto unknown;
        }

      if (p[0] == '.' && ISDIGIT (p[1]))
        {
          /* Nested subprogram.  */
          p += 2;
          while (ISDIGIT (*p))
            p++;
        }
      if (*p == 0)
        {
          /* End of mangled name.  */
          break;
        }
      else
        goto unknown;
    }
  *d = 0;
  return demangled;

 unknown:
  XDELETEVEC (demangled);
  len0 = strlen (mangled);
  demangled = XNEWVEC (char, len0 + 3);

  if (mangled[0] == '<')
     strcpy (demangled, mangled);
  else
    sprintf (demangled, "<%s>", mangled);

  return demangled;
}
