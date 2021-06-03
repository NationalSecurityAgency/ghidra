/* ###
 * IP: LGPL 2.1
 */
/* Demangler for GNU C++
   Copyright 1989, 1991, 1994, 1995, 1996, 1997, 1998, 1999,
   2000, 2001, 2002, 2003, 2004, 2010 Free Software Foundation, Inc.
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
Boston, MA 02110-1301, USA.  


					CHANGE NOTICE:
This file was changed on July 1st, 2014.			

*/

/* This file exports two functions; cplus_mangle_opname and cplus_demangle.

   This file imports xmalloc and xrealloc, which are like malloc and
   realloc except that they generate a fatal error if there is no
   available memory.  */

/* This file lives in both GCC and libiberty.  When making changes, please
   try not to break either.  */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "safe-ctype.h"

#include <sys/types.h>
#include <string.h>
#include <stdio.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
void * malloc ();
void * realloc ();
#endif

#include <demangle.h>
#undef CURRENT_DEMANGLING_STYLE
#define CURRENT_DEMANGLING_STYLE work->options

#include "libiberty.h"

#define min(X,Y) (((X) < (Y)) ? (X) : (Y))

/* A value at least one greater than the maximum number of characters
   that will be output when using the `%d' format with `printf'.  */
#define INTBUF_SIZE 32

extern void fancy_abort (void) ATTRIBUTE_NORETURN;

/* In order to allow a single demangler executable to demangle strings
   using various common values of CPLUS_MARKER, as well as any specific
   one set at compile time, we maintain a string containing all the
   commonly used ones, and check to see if the marker we are looking for
   is in that string.  CPLUS_MARKER is usually '$' on systems where the
   assembler can deal with that.  Where the assembler can't, it's usually
   '.' (but on many systems '.' is used for other things).  We put the
   current defined CPLUS_MARKER first (which defaults to '$'), followed
   by the next most common value, followed by an explicit '$' in case
   the value of CPLUS_MARKER is not '$'.

   We could avoid this if we could just get g++ to tell us what the actual
   cplus marker character is as part of the debug information, perhaps by
   ensuring that it is the character that terminates the gcc<n>_compiled
   marker symbol (FIXME).  */

#if !defined (CPLUS_MARKER)
#define CPLUS_MARKER '$'
#endif

enum demangling_styles current_demangling_style = auto_demangling;

static char cplus_markers[] = { CPLUS_MARKER, '.', '$', '\0' };

static char char_str[2] = { '\000', '\000' };

void
set_cplus_marker_for_demangling (int ch)
{
  cplus_markers[0] = ch;
}

typedef struct string		/* Beware: these aren't required to be */
{				/*  '\0' terminated.  */
  char *b;			/* pointer to start of string */
  char *p;			/* pointer after last character */
  char *e;			/* pointer after end of allocated space */
} string;

/* Stuff that is shared between sub-routines.
   Using a shared structure allows cplus_demangle to be reentrant.  */

struct work_stuff
{
  int options;
  char **typevec;
  char **ktypevec;
  char **btypevec;
  int numk;
  int numb;
  int ksize;
  int bsize;
  int ntypes;
  int typevec_size;
  int constructor;
  int destructor;
  int static_type;	/* A static member function */
  int temp_start;       /* index in demangled to start of template args */
  int type_quals;       /* The type qualifiers.  */
  int dllimported;	/* Symbol imported from a PE DLL */
  char **tmpl_argvec;   /* Template function arguments. */
  int ntmpl_args;       /* The number of template function arguments. */
  int forgetting_types; /* Nonzero if we are not remembering the types
			   we see.  */
  string* previous_argument; /* The last function argument demangled.  */
  int nrepeats;         /* The number of times to repeat the previous
			   argument.  */
};

#define PRINT_ANSI_QUALIFIERS (work -> options & DMGL_ANSI)
#define PRINT_ARG_TYPES       (work -> options & DMGL_PARAMS)

static const struct optable
{
  const char *const in;
  const char *const out;
  const int flags;
} optable[] = {
  {"nw",	  " new",	DMGL_ANSI},	/* new (1.92,	 ansi) */
  {"dl",	  " delete",	DMGL_ANSI},	/* new (1.92,	 ansi) */
  {"new",	  " new",	0},		/* old (1.91,	 and 1.x) */
  {"delete",	  " delete",	0},		/* old (1.91,	 and 1.x) */
  {"vn",	  " new []",	DMGL_ANSI},	/* GNU, pending ansi */
  {"vd",	  " delete []",	DMGL_ANSI},	/* GNU, pending ansi */
  {"as",	  "=",		DMGL_ANSI},	/* ansi */
  {"ne",	  "!=",		DMGL_ANSI},	/* old, ansi */
  {"eq",	  "==",		DMGL_ANSI},	/* old,	ansi */
  {"ge",	  ">=",		DMGL_ANSI},	/* old,	ansi */
  {"gt",	  ">",		DMGL_ANSI},	/* old,	ansi */
  {"le",	  "<=",		DMGL_ANSI},	/* old,	ansi */
  {"lt",	  "<",		DMGL_ANSI},	/* old,	ansi */
  {"plus",	  "+",		0},		/* old */
  {"pl",	  "+",		DMGL_ANSI},	/* ansi */
  {"apl",	  "+=",		DMGL_ANSI},	/* ansi */
  {"minus",	  "-",		0},		/* old */
  {"mi",	  "-",		DMGL_ANSI},	/* ansi */
  {"ami",	  "-=",		DMGL_ANSI},	/* ansi */
  {"mult",	  "*",		0},		/* old */
  {"ml",	  "*",		DMGL_ANSI},	/* ansi */
  {"amu",	  "*=",		DMGL_ANSI},	/* ansi (ARM/Lucid) */
  {"aml",	  "*=",		DMGL_ANSI},	/* ansi (GNU/g++) */
  {"convert",	  "+",		0},		/* old (unary +) */
  {"negate",	  "-",		0},		/* old (unary -) */
  {"trunc_mod",	  "%",		0},		/* old */
  {"md",	  "%",		DMGL_ANSI},	/* ansi */
  {"amd",	  "%=",		DMGL_ANSI},	/* ansi */
  {"trunc_div",	  "/",		0},		/* old */
  {"dv",	  "/",		DMGL_ANSI},	/* ansi */
  {"adv",	  "/=",		DMGL_ANSI},	/* ansi */
  {"truth_andif", "&&",		0},		/* old */
  {"aa",	  "&&",		DMGL_ANSI},	/* ansi */
  {"truth_orif",  "||",		0},		/* old */
  {"oo",	  "||",		DMGL_ANSI},	/* ansi */
  {"truth_not",	  "!",		0},		/* old */
  {"nt",	  "!",		DMGL_ANSI},	/* ansi */
  {"postincrement","++",	0},		/* old */
  {"pp",	  "++",		DMGL_ANSI},	/* ansi */
  {"postdecrement","--",	0},		/* old */
  {"mm",	  "--",		DMGL_ANSI},	/* ansi */
  {"bit_ior",	  "|",		0},		/* old */
  {"or",	  "|",		DMGL_ANSI},	/* ansi */
  {"aor",	  "|=",		DMGL_ANSI},	/* ansi */
  {"bit_xor",	  "^",		0},		/* old */
  {"er",	  "^",		DMGL_ANSI},	/* ansi */
  {"aer",	  "^=",		DMGL_ANSI},	/* ansi */
  {"bit_and",	  "&",		0},		/* old */
  {"ad",	  "&",		DMGL_ANSI},	/* ansi */
  {"aad",	  "&=",		DMGL_ANSI},	/* ansi */
  {"bit_not",	  "~",		0},		/* old */
  {"co",	  "~",		DMGL_ANSI},	/* ansi */
  {"call",	  "()",		0},		/* old */
  {"cl",	  "()",		DMGL_ANSI},	/* ansi */
  {"alshift",	  "<<",		0},		/* old */
  {"ls",	  "<<",		DMGL_ANSI},	/* ansi */
  {"als",	  "<<=",	DMGL_ANSI},	/* ansi */
  {"arshift",	  ">>",		0},		/* old */
  {"rs",	  ">>",		DMGL_ANSI},	/* ansi */
  {"ars",	  ">>=",	DMGL_ANSI},	/* ansi */
  {"component",	  "->",		0},		/* old */
  {"pt",	  "->",		DMGL_ANSI},	/* ansi; Lucid C++ form */
  {"rf",	  "->",		DMGL_ANSI},	/* ansi; ARM/GNU form */
  {"indirect",	  "*",		0},		/* old */
  {"method_call",  "->()",	0},		/* old */
  {"addr",	  "&",		0},		/* old (unary &) */
  {"array",	  "[]",		0},		/* old */
  {"vc",	  "[]",		DMGL_ANSI},	/* ansi */
  {"compound",	  ", ",		0},		/* old */
  {"cm",	  ", ",		DMGL_ANSI},	/* ansi */
  {"cond",	  "?:",		0},		/* old */
  {"cn",	  "?:",		DMGL_ANSI},	/* pseudo-ansi */
  {"max",	  ">?",		0},		/* old */
  {"mx",	  ">?",		DMGL_ANSI},	/* pseudo-ansi */
  {"min",	  "<?",		0},		/* old */
  {"mn",	  "<?",		DMGL_ANSI},	/* pseudo-ansi */
  {"nop",	  "",		0},		/* old (for operator=) */
  {"rm",	  "->*",	DMGL_ANSI},	/* ansi */
  {"sz",          "sizeof ",    DMGL_ANSI}      /* pseudo-ansi */
};

/* These values are used to indicate the various type varieties.
   They are all non-zero so that they can be used as `success'
   values.  */
typedef enum type_kind_t
{
  tk_none,
  tk_pointer,
  tk_reference,
  tk_integral,
  tk_bool,
  tk_char,
  tk_real
} type_kind_t;

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
    GNU_DEMANGLING_STYLE_STRING,
      gnu_demangling,
      "GNU (g++) style demangling"
  }
  ,
  {
    LUCID_DEMANGLING_STYLE_STRING,
      lucid_demangling,
      "Lucid (lcc) style demangling"
  }
  ,
  {
    ARM_DEMANGLING_STYLE_STRING,
      arm_demangling,
      "ARM style demangling"
  }
  ,
  {
    HP_DEMANGLING_STYLE_STRING,
      hp_demangling,
      "HP (aCC) style demangling"
  }
  ,
  {
    EDG_DEMANGLING_STYLE_STRING,
      edg_demangling,
      "EDG style demangling"
  }
  ,
  {
    GNU_V3_DEMANGLING_STYLE_STRING,
    gnu_v3_demangling,
    "GNU (g++) V3 ABI-style demangling"
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
    NULL, unknown_demangling, NULL
  }
};

#define STRING_EMPTY(str)	((str) -> b == (str) -> p)
#define APPEND_BLANK(str)	{if (!STRING_EMPTY(str)) \
    string_append(str, " ");}
#define LEN_STRING(str)         ( (STRING_EMPTY(str))?0:((str)->p - (str)->b))

/* The scope separator appropriate for the language being demangled.  */

#define SCOPE_STRING(work) ((work->options & DMGL_JAVA) ? "." : "::")

#define ARM_VTABLE_STRING "__vtbl__"	/* Lucid/ARM virtual table prefix */
#define ARM_VTABLE_STRLEN 8		/* strlen (ARM_VTABLE_STRING) */

/* Prototypes for local functions */

static void delete_work_stuff (struct work_stuff *);

static void delete_non_B_K_work_stuff (struct work_stuff *);

static char *mop_up (struct work_stuff *, string *, int);

static void squangle_mop_up (struct work_stuff *);

static void work_stuff_copy_to_from (struct work_stuff *, struct work_stuff *);

#if 0
static int
demangle_method_args (struct work_stuff *, const char **, string *);
#endif

static char *
internal_cplus_demangle (struct work_stuff *, const char *);

static int
demangle_template_template_parm (struct work_stuff *work,
                                 const char **, string *);

static int
demangle_template (struct work_stuff *work, const char **, string *,
                   string *, int, int);

static int
arm_pt (struct work_stuff *, const char *, int, const char **,
        const char **);

static int
demangle_class_name (struct work_stuff *, const char **, string *);

static int
demangle_qualified (struct work_stuff *, const char **, string *,
                    int, int);

static int demangle_class (struct work_stuff *, const char **, string *);

static int demangle_fund_type (struct work_stuff *, const char **, string *);

static int demangle_signature (struct work_stuff *, const char **, string *);

static int demangle_prefix (struct work_stuff *, const char **, string *);

static int gnu_special (struct work_stuff *, const char **, string *);

static int arm_special (const char **, string *);

static void string_need (string *, int);

static void string_delete (string *);

static void
string_init (string *);

static void string_clear (string *);

#if 0
static int string_empty (string *);
#endif

static void string_append (string *, const char *);

static void string_appends (string *, string *);

static void string_appendn (string *, const char *, int);

static void string_prepend (string *, const char *);

static void string_prependn (string *, const char *, int);

static void string_append_template_idx (string *, int);

static int get_count (const char **, int *);

static int consume_count (const char **);

static int consume_count_with_underscores (const char**);

static int demangle_args (struct work_stuff *, const char **, string *);

static int demangle_nested_args (struct work_stuff*, const char**, string*);

static int do_type (struct work_stuff *, const char **, string *);

static int do_arg (struct work_stuff *, const char **, string *);

static int
demangle_function_name (struct work_stuff *, const char **, string *,
                        const char *);

static int
iterate_demangle_function (struct work_stuff *,
                           const char **, string *, const char *);

static void remember_type (struct work_stuff *, const char *, int);

static void remember_Btype (struct work_stuff *, const char *, int, int);

static int register_Btype (struct work_stuff *);

static void remember_Ktype (struct work_stuff *, const char *, int);

static void forget_types (struct work_stuff *);

static void forget_B_and_K_types (struct work_stuff *);

static void string_prepends (string *, string *);

static int
demangle_template_value_parm (struct work_stuff*, const char**,
                              string*, type_kind_t);

static int
do_hpacc_template_const_value (struct work_stuff *, const char **, string *);

static int
do_hpacc_template_literal (struct work_stuff *, const char **, string *);

static int snarf_numeric_literal (const char **, string *);

/* There is a TYPE_QUAL value for each type qualifier.  They can be
   combined by bitwise-or to form the complete set of qualifiers for a
   type.  */

#define TYPE_UNQUALIFIED   0x0
#define TYPE_QUAL_CONST    0x1
#define TYPE_QUAL_VOLATILE 0x2
#define TYPE_QUAL_RESTRICT 0x4

static int code_for_qualifier (int);

static const char* qualifier_string (int);

static const char* demangle_qualifier (int);

static int demangle_expression (struct work_stuff *, const char **, string *, 
                                type_kind_t);

static int
demangle_integral_value (struct work_stuff *, const char **, string *);

static int
demangle_real_value (struct work_stuff *, const char **, string *);

static void
demangle_arm_hp_template (struct work_stuff *, const char **, int, string *);

static void
recursively_demangle (struct work_stuff *, const char **, string *, int);

/* Translate count to integer, consuming tokens in the process.
   Conversion terminates on the first non-digit character.

   Trying to consume something that isn't a count results in no
   consumption of input and a return of -1.

   Overflow consumes the rest of the digits, and returns -1.  */

static int
consume_count (const char **type)
{
  int count = 0;

  if (! ISDIGIT ((unsigned char)**type))
    return -1;

  while (ISDIGIT ((unsigned char)**type))
    {
      count *= 10;

      /* Check for overflow.
	 We assume that count is represented using two's-complement;
	 no power of two is divisible by ten, so if an overflow occurs
	 when multiplying by ten, the result will not be a multiple of
	 ten.  */
      if ((count % 10) != 0)
	{
	  while (ISDIGIT ((unsigned char) **type))
	    (*type)++;
	  return -1;
	}

      count += **type - '0';
      (*type)++;
    }

  if (count < 0)
    count = -1;

  return (count);
}


/* Like consume_count, but for counts that are preceded and followed
   by '_' if they are greater than 10.  Also, -1 is returned for
   failure, since 0 can be a valid value.  */

static int
consume_count_with_underscores (const char **mangled)
{
  int idx;

  if (**mangled == '_')
    {
      (*mangled)++;
      if (!ISDIGIT ((unsigned char)**mangled))
	return -1;

      idx = consume_count (mangled);
      if (**mangled != '_')
	/* The trailing underscore was missing. */
	return -1;

      (*mangled)++;
    }
  else
    {
      if (**mangled < '0' || **mangled > '9')
	return -1;

      idx = **mangled - '0';
      (*mangled)++;
    }

  return idx;
}

/* C is the code for a type-qualifier.  Return the TYPE_QUAL
   corresponding to this qualifier.  */

static int
code_for_qualifier (int c)
{
  switch (c)
    {
    case 'C':
      return TYPE_QUAL_CONST;

    case 'V':
      return TYPE_QUAL_VOLATILE;

    case 'u':
      return TYPE_QUAL_RESTRICT;

    default:
      break;
    }

  /* C was an invalid qualifier.  */
  abort ();
}

/* Return the string corresponding to the qualifiers given by
   TYPE_QUALS.  */

static const char*
qualifier_string (int type_quals)
{
  switch (type_quals)
    {
    case TYPE_UNQUALIFIED:
      return "";

    case TYPE_QUAL_CONST:
      return "const";

    case TYPE_QUAL_VOLATILE:
      return "volatile";

    case TYPE_QUAL_RESTRICT:
      return "__restrict";

    case TYPE_QUAL_CONST | TYPE_QUAL_VOLATILE:
      return "const volatile";

    case TYPE_QUAL_CONST | TYPE_QUAL_RESTRICT:
      return "const __restrict";

    case TYPE_QUAL_VOLATILE | TYPE_QUAL_RESTRICT:
      return "volatile __restrict";

    case TYPE_QUAL_CONST | TYPE_QUAL_VOLATILE | TYPE_QUAL_RESTRICT:
      return "const volatile __restrict";

    default:
      break;
    }

  /* TYPE_QUALS was an invalid qualifier set.  */
  abort ();
}

/* C is the code for a type-qualifier.  Return the string
   corresponding to this qualifier.  This function should only be
   called with a valid qualifier code.  */

static const char*
demangle_qualifier (int c)
{
  return qualifier_string (code_for_qualifier (c));
}

int
cplus_demangle_opname (const char *opname, char *result, int options)
{
  int len, len1, ret;
  string type;
  struct work_stuff work[1];
  const char *tem;

  len = strlen(opname);
  result[0] = '\0';
  ret = 0;
  memset ((char *) work, 0, sizeof (work));
  work->options = options;

  if (opname[0] == '_' && opname[1] == '_'
      && opname[2] == 'o' && opname[3] == 'p')
    {
      /* ANSI.  */
      /* type conversion operator.  */
      tem = opname + 4;
      if (do_type (work, &tem, &type))
	{
	  strcat (result, "operator ");
	  strncat (result, type.b, type.p - type.b);
	  string_delete (&type);
	  ret = 1;
	}
    }
  else if (opname[0] == '_' && opname[1] == '_'
	   && ISLOWER((unsigned char)opname[2])
	   && ISLOWER((unsigned char)opname[3]))
    {
      if (opname[4] == '\0')
	{
	  /* Operator.  */
	  size_t i;
	  for (i = 0; i < ARRAY_SIZE (optable); i++)
	    {
	      if (strlen (optable[i].in) == 2
		  && memcmp (optable[i].in, opname + 2, 2) == 0)
		{
		  strcat (result, "operator");
		  strcat (result, optable[i].out);
		  ret = 1;
		  break;
		}
	    }
	}
      else
	{
	  if (opname[2] == 'a' && opname[5] == '\0')
	    {
	      /* Assignment.  */
	      size_t i;
	      for (i = 0; i < ARRAY_SIZE (optable); i++)
		{
		  if (strlen (optable[i].in) == 3
		      && memcmp (optable[i].in, opname + 2, 3) == 0)
		    {
		      strcat (result, "operator");
		      strcat (result, optable[i].out);
		      ret = 1;
		      break;
		    }
		}
	    }
	}
    }
  else if (len >= 3
	   && opname[0] == 'o'
	   && opname[1] == 'p'
	   && strchr (cplus_markers, opname[2]) != NULL)
    {
      /* see if it's an assignment expression */
      if (len >= 10 /* op$assign_ */
	  && memcmp (opname + 3, "assign_", 7) == 0)
	{
	  size_t i;
	  for (i = 0; i < ARRAY_SIZE (optable); i++)
	    {
	      len1 = len - 10;
	      if ((int) strlen (optable[i].in) == len1
		  && memcmp (optable[i].in, opname + 10, len1) == 0)
		{
		  strcat (result, "operator");
		  strcat (result, optable[i].out);
		  strcat (result, "=");
		  ret = 1;
		  break;
		}
	    }
	}
      else
	{
	  size_t i;
	  for (i = 0; i < ARRAY_SIZE (optable); i++)
	    {
	      len1 = len - 3;
	      if ((int) strlen (optable[i].in) == len1
		  && memcmp (optable[i].in, opname + 3, len1) == 0)
		{
		  strcat (result, "operator");
		  strcat (result, optable[i].out);
		  ret = 1;
		  break;
		}
	    }
	}
    }
  else if (len >= 5 && memcmp (opname, "type", 4) == 0
	   && strchr (cplus_markers, opname[4]) != NULL)
    {
      /* type conversion operator */
      tem = opname + 5;
      if (do_type (work, &tem, &type))
	{
	  strcat (result, "operator ");
	  strncat (result, type.b, type.p - type.b);
	  string_delete (&type);
	  ret = 1;
	}
    }
  squangle_mop_up (work);
  return ret;

}

/* Takes operator name as e.g. "++" and returns mangled
   operator name (e.g. "postincrement_expr"), or NULL if not found.

   If OPTIONS & DMGL_ANSI == 1, return the ANSI name;
   if OPTIONS & DMGL_ANSI == 0, return the old GNU name.  */

const char *
cplus_mangle_opname (const char *opname, int options)
{
  size_t i;
  int len;

  len = strlen (opname);
  for (i = 0; i < ARRAY_SIZE (optable); i++)
    {
      if ((int) strlen (optable[i].out) == len
	  && (options & DMGL_ANSI) == (optable[i].flags & DMGL_ANSI)
	  && memcmp (optable[i].out, opname, len) == 0)
	return optable[i].in;
    }
  return (0);
}

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

   The OPTIONS arg may contain one or more of the following bits:

   	DMGL_ANSI	ANSI qualifiers such as `const' and `void' are
			included.
	DMGL_PARAMS	Function parameters are included.

   For example,

   cplus_demangle ("foo__1Ai", DMGL_PARAMS)		=> "A::foo(int)"
   cplus_demangle ("foo__1Ai", DMGL_PARAMS | DMGL_ANSI)	=> "A::foo(int)"
   cplus_demangle ("foo__1Ai", 0)			=> "A::foo"

   cplus_demangle ("foo__1Afe", DMGL_PARAMS)		=> "A::foo(float,...)"
   cplus_demangle ("foo__1Afe", DMGL_PARAMS | DMGL_ANSI)=> "A::foo(float,...)"
   cplus_demangle ("foo__1Afe", 0)			=> "A::foo"

   Note that any leading underscores, or other such characters prepended by
   the compilation system, are presumed to have already been stripped from
   MANGLED.  */

char *
cplus_demangle (const char *mangled, int options)
{
  char *ret;
  struct work_stuff work[1];

  if (current_demangling_style == no_demangling)
    return xstrdup (mangled);

  memset ((char *) work, 0, sizeof (work));
  work->options = options;
  if ((work->options & DMGL_STYLE_MASK) == 0)
    work->options |= (int) current_demangling_style & DMGL_STYLE_MASK;

  /* The V3 ABI demangling is implemented elsewhere.  */
  if (GNU_V3_DEMANGLING || AUTO_DEMANGLING)
    {
      ret = cplus_demangle_v3 (mangled, work->options);
      if (ret || GNU_V3_DEMANGLING)
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

  ret = internal_cplus_demangle (work, mangled);
  squangle_mop_up (work);
  return (ret);
}

/* Demangle ada names.  The encoding is documented in gcc/ada/exp_dbug.ads.  */

char *
ada_demangle (const char *mangled, int option ATTRIBUTE_UNUSED)
{
  int len0;
  const char* p;
  char *d;
  char *demangled;
  
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
  len0 = strlen (mangled);
  demangled = XNEWVEC (char, len0 + 3);

  if (mangled[0] == '<')
     strcpy (demangled, mangled);
  else
    sprintf (demangled, "<%s>", mangled);

  return demangled;
}

/* This function performs most of what cplus_demangle use to do, but
   to be able to demangle a name with a B, K or n code, we need to
   have a longer term memory of what types have been seen. The original
   now initializes and cleans up the squangle code info, while internal
   calls go directly to this routine to avoid resetting that info. */

static char *
internal_cplus_demangle (struct work_stuff *work, const char *mangled)
{

  string decl;
  int success = 0;
  char *demangled = NULL;
  int s1, s2, s3, s4;
  s1 = work->constructor;
  s2 = work->destructor;
  s3 = work->static_type;
  s4 = work->type_quals;
  work->constructor = work->destructor = 0;
  work->type_quals = TYPE_UNQUALIFIED;
  work->dllimported = 0;

  if ((mangled != NULL) && (*mangled != '\0'))
    {
      string_init (&decl);

      /* First check to see if gnu style demangling is active and if the
	 string to be demangled contains a CPLUS_MARKER.  If so, attempt to
	 recognize one of the gnu special forms rather than looking for a
	 standard prefix.  In particular, don't worry about whether there
	 is a "__" string in the mangled string.  Consider "_$_5__foo" for
	 example.  */

      if ((AUTO_DEMANGLING || GNU_DEMANGLING))
	{
	  success = gnu_special (work, &mangled, &decl);
	}
      if (!success)
	{
	  success = demangle_prefix (work, &mangled, &decl);
	}
      if (success && (*mangled != '\0'))
	{
	  success = demangle_signature (work, &mangled, &decl);
	}
      if (work->constructor == 2)
        {
          string_prepend (&decl, "global constructors keyed to ");
          work->constructor = 0;
        }
      else if (work->destructor == 2)
        {
          string_prepend (&decl, "global destructors keyed to ");
          work->destructor = 0;
        }
      else if (work->dllimported == 1)
        {
          string_prepend (&decl, "import stub for ");
          work->dllimported = 0;
        }
      demangled = mop_up (work, &decl, success);
    }
  work->constructor = s1;
  work->destructor = s2;
  work->static_type = s3;
  work->type_quals = s4;
  return demangled;
}


/* Clear out and squangling related storage */
static void
squangle_mop_up (struct work_stuff *work)
{
  /* clean up the B and K type mangling types. */
  forget_B_and_K_types (work);
  if (work -> btypevec != NULL)
    {
      free ((char *) work -> btypevec);
    }
  if (work -> ktypevec != NULL)
    {
      free ((char *) work -> ktypevec);
    }
}


/* Copy the work state and storage.  */

static void
work_stuff_copy_to_from (struct work_stuff *to, struct work_stuff *from)
{
  int i;

  delete_work_stuff (to);

  /* Shallow-copy scalars.  */
  memcpy (to, from, sizeof (*to));

  /* Deep-copy dynamic storage.  */
  if (from->typevec_size)
    to->typevec = XNEWVEC (char *, from->typevec_size);

  for (i = 0; i < from->ntypes; i++)
    {
      int len = strlen (from->typevec[i]) + 1;

      to->typevec[i] = XNEWVEC (char, len);
      memcpy (to->typevec[i], from->typevec[i], len);
    }

  if (from->ksize)
    to->ktypevec = XNEWVEC (char *, from->ksize);

  for (i = 0; i < from->numk; i++)
    {
      int len = strlen (from->ktypevec[i]) + 1;

      to->ktypevec[i] = XNEWVEC (char, len);
      memcpy (to->ktypevec[i], from->ktypevec[i], len);
    }

  if (from->bsize)
    to->btypevec = XNEWVEC (char *, from->bsize);

  for (i = 0; i < from->numb; i++)
    {
      int len = strlen (from->btypevec[i]) + 1;

      to->btypevec[i] = XNEWVEC (char , len);
      memcpy (to->btypevec[i], from->btypevec[i], len);
    }

  if (from->ntmpl_args)
    to->tmpl_argvec = XNEWVEC (char *, from->ntmpl_args);

  for (i = 0; i < from->ntmpl_args; i++)
    {
      int len = strlen (from->tmpl_argvec[i]) + 1;

      to->tmpl_argvec[i] = XNEWVEC (char, len);
      memcpy (to->tmpl_argvec[i], from->tmpl_argvec[i], len);
    }

  if (from->previous_argument)
    {
      to->previous_argument = XNEW (string);
      string_init (to->previous_argument);
      string_appends (to->previous_argument, from->previous_argument);
    }
}


/* Delete dynamic stuff in work_stuff that is not to be re-used.  */

static void
delete_non_B_K_work_stuff (struct work_stuff *work)
{
  /* Discard the remembered types, if any.  */

  forget_types (work);
  if (work -> typevec != NULL)
    {
      free ((char *) work -> typevec);
      work -> typevec = NULL;
      work -> typevec_size = 0;
    }
  if (work->tmpl_argvec)
    {
      int i;

      for (i = 0; i < work->ntmpl_args; i++)
	free ((char*) work->tmpl_argvec[i]);

      free ((char*) work->tmpl_argvec);
      work->tmpl_argvec = NULL;
    }
  if (work->previous_argument)
    {
      string_delete (work->previous_argument);
      free ((char*) work->previous_argument);
      work->previous_argument = NULL;
    }
}


/* Delete all dynamic storage in work_stuff.  */
static void
delete_work_stuff (struct work_stuff *work)
{
  delete_non_B_K_work_stuff (work);
  squangle_mop_up (work);
}


/* Clear out any mangled storage */

static char *
mop_up (struct work_stuff *work, string *declp, int success)
{
  char *demangled = NULL;

  delete_non_B_K_work_stuff (work);

  /* If demangling was successful, ensure that the demangled string is null
     terminated and return it.  Otherwise, free the demangling decl.  */

  if (!success)
    {
      string_delete (declp);
    }
  else
    {
      string_appendn (declp, "", 1);
      demangled = declp->b;
    }
  return (demangled);
}

/*

LOCAL FUNCTION

	demangle_signature -- demangle the signature part of a mangled name

SYNOPSIS

	static int
	demangle_signature (struct work_stuff *work, const char **mangled,
			    string *declp);

DESCRIPTION

	Consume and demangle the signature portion of the mangled name.

	DECLP is the string where demangled output is being built.  At
	entry it contains the demangled root name from the mangled name
	prefix.  I.E. either a demangled operator name or the root function
	name.  In some special cases, it may contain nothing.

	*MANGLED points to the current unconsumed location in the mangled
	name.  As tokens are consumed and demangling is performed, the
	pointer is updated to continuously point at the next token to
	be consumed.

	Demangling GNU style mangled names is nasty because there is no
	explicit token that marks the start of the outermost function
	argument list.  */

static int
demangle_signature (struct work_stuff *work,
                    const char **mangled, string *declp)
{
  int success = 1;
  int func_done = 0;
  int expect_func = 0;
  int expect_return_type = 0;
  const char *oldmangled = NULL;
  string trawname;
  string tname;

  while (success && (**mangled != '\0'))
    {
      switch (**mangled)
	{
	case 'Q':
	  oldmangled = *mangled;
	  success = demangle_qualified (work, mangled, declp, 1, 0);
	  if (success)
	    remember_type (work, oldmangled, *mangled - oldmangled);
	  if (AUTO_DEMANGLING || GNU_DEMANGLING)
	    expect_func = 1;
	  oldmangled = NULL;
	  break;

        case 'K':
	  oldmangled = *mangled;
	  success = demangle_qualified (work, mangled, declp, 1, 0);
	  if (AUTO_DEMANGLING || GNU_DEMANGLING)
	    {
	      expect_func = 1;
	    }
	  oldmangled = NULL;
	  break;

	case 'S':
	  /* Static member function */
	  if (oldmangled == NULL)
	    {
	      oldmangled = *mangled;
	    }
	  (*mangled)++;
	  work -> static_type = 1;
	  break;

	case 'C':
	case 'V':
	case 'u':
	  work->type_quals |= code_for_qualifier (**mangled);

	  /* a qualified member function */
	  if (oldmangled == NULL)
	    oldmangled = *mangled;
	  (*mangled)++;
	  break;

	case 'L':
	  /* Local class name follows after "Lnnn_" */
	  if (HP_DEMANGLING)
	    {
	      while (**mangled && (**mangled != '_'))
		(*mangled)++;
	      if (!**mangled)
		success = 0;
	      else
		(*mangled)++;
	    }
	  else
	    success = 0;
	  break;

	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
	  if (oldmangled == NULL)
	    {
	      oldmangled = *mangled;
	    }
          work->temp_start = -1; /* uppermost call to demangle_class */
	  success = demangle_class (work, mangled, declp);
	  if (success)
	    {
	      remember_type (work, oldmangled, *mangled - oldmangled);
	    }
	  if (AUTO_DEMANGLING || GNU_DEMANGLING || EDG_DEMANGLING)
	    {
              /* EDG and others will have the "F", so we let the loop cycle
                 if we are looking at one. */
              if (**mangled != 'F')
                 expect_func = 1;
	    }
	  oldmangled = NULL;
	  break;

	case 'B':
	  {
	    string s;
	    success = do_type (work, mangled, &s);
	    if (success)
	      {
		string_append (&s, SCOPE_STRING (work));
		string_prepends (declp, &s);
		string_delete (&s);
	      }
	    oldmangled = NULL;
	    expect_func = 1;
	  }
	  break;

	case 'F':
	  /* Function */
	  /* ARM/HP style demangling includes a specific 'F' character after
	     the class name.  For GNU style, it is just implied.  So we can
	     safely just consume any 'F' at this point and be compatible
	     with either style.  */

	  oldmangled = NULL;
	  func_done = 1;
	  (*mangled)++;

	  /* For lucid/ARM/HP style we have to forget any types we might
	     have remembered up to this point, since they were not argument
	     types.  GNU style considers all types seen as available for
	     back references.  See comment in demangle_args() */

	  if (LUCID_DEMANGLING || ARM_DEMANGLING || HP_DEMANGLING || EDG_DEMANGLING)
	    {
	      forget_types (work);
	    }
	  success = demangle_args (work, mangled, declp);
	  /* After picking off the function args, we expect to either
	     find the function return type (preceded by an '_') or the
	     end of the string. */
	  if (success && (AUTO_DEMANGLING || EDG_DEMANGLING) && **mangled == '_')
	    {
	      ++(*mangled);
              /* At this level, we do not care about the return type. */
              success = do_type (work, mangled, &tname);
              string_delete (&tname);
            }

	  break;

	case 't':
	  /* G++ Template */
	  string_init(&trawname);
	  string_init(&tname);
	  if (oldmangled == NULL)
	    {
	      oldmangled = *mangled;
	    }
	  success = demangle_template (work, mangled, &tname,
				       &trawname, 1, 1);
	  if (success)
	    {
	      remember_type (work, oldmangled, *mangled - oldmangled);
	    }
	  string_append (&tname, SCOPE_STRING (work));

	  string_prepends(declp, &tname);
	  if (work -> destructor & 1)
	    {
	      string_prepend (&trawname, "~");
	      string_appends (declp, &trawname);
	      work->destructor -= 1;
	    }
	  if ((work->constructor & 1) || (work->destructor & 1))
	    {
	      string_appends (declp, &trawname);
	      work->constructor -= 1;
	    }
	  string_delete(&trawname);
	  string_delete(&tname);
	  oldmangled = NULL;
	  expect_func = 1;
	  break;

	case '_':
	  if ((AUTO_DEMANGLING || GNU_DEMANGLING) && expect_return_type)
	    {
	      /* Read the return type. */
	      string return_type;

	      (*mangled)++;
	      success = do_type (work, mangled, &return_type);
	      APPEND_BLANK (&return_type);

	      string_prepends (declp, &return_type);
	      string_delete (&return_type);
	      break;
	    }
	  else
	    /* At the outermost level, we cannot have a return type specified,
	       so if we run into another '_' at this point we are dealing with
	       a mangled name that is either bogus, or has been mangled by
	       some algorithm we don't know how to deal with.  So just
	       reject the entire demangling.  */
            /* However, "_nnn" is an expected suffix for alternate entry point
               numbered nnn for a function, with HP aCC, so skip over that
               without reporting failure. pai/1997-09-04 */
            if (HP_DEMANGLING)
              {
                (*mangled)++;
                while (**mangled && ISDIGIT ((unsigned char)**mangled))
                  (*mangled)++;
              }
            else
	      success = 0;
	  break;

	case 'H':
	  if (AUTO_DEMANGLING || GNU_DEMANGLING)
	    {
	      /* A G++ template function.  Read the template arguments. */
	      success = demangle_template (work, mangled, declp, 0, 0,
					   0);
	      if (!(work->constructor & 1))
		expect_return_type = 1;
	      (*mangled)++;
	      break;
	    }
	  else
	    /* fall through */
	    {;}

	default:
	  if (AUTO_DEMANGLING || GNU_DEMANGLING)
	    {
	      /* Assume we have stumbled onto the first outermost function
		 argument token, and start processing args.  */
	      func_done = 1;
	      success = demangle_args (work, mangled, declp);
	    }
	  else
	    {
	      /* Non-GNU demanglers use a specific token to mark the start
		 of the outermost function argument tokens.  Typically 'F',
		 for ARM/HP-demangling, for example.  So if we find something
		 we are not prepared for, it must be an error.  */
	      success = 0;
	    }
	  break;
	}
      /*
	if (AUTO_DEMANGLING || GNU_DEMANGLING)
	*/
      {
	if (success && expect_func)
	  {
	    func_done = 1;
              if (LUCID_DEMANGLING || ARM_DEMANGLING || EDG_DEMANGLING)
                {
                  forget_types (work);
                }
	    success = demangle_args (work, mangled, declp);
	    /* Since template include the mangling of their return types,
	       we must set expect_func to 0 so that we don't try do
	       demangle more arguments the next time we get here.  */
	    expect_func = 0;
	  }
      }
    }
  if (success && !func_done)
    {
      if (AUTO_DEMANGLING || GNU_DEMANGLING)
	{
	  /* With GNU style demangling, bar__3foo is 'foo::bar(void)', and
	     bar__3fooi is 'foo::bar(int)'.  We get here when we find the
	     first case, and need to ensure that the '(void)' gets added to
	     the current declp.  Note that with ARM/HP, the first case
	     represents the name of a static data member 'foo::bar',
	     which is in the current declp, so we leave it alone.  */
	  success = demangle_args (work, mangled, declp);
	}
    }
  if (success && PRINT_ARG_TYPES)
    {
      if (work->static_type)
	string_append (declp, " static");
      if (work->type_quals != TYPE_UNQUALIFIED)
	{
	  APPEND_BLANK (declp);
	  string_append (declp, qualifier_string (work->type_quals));
	}
    }

  return (success);
}

#if 0

static int
demangle_method_args (struct work_stuff *work, const char **mangled,
                      string *declp)
{
  int success = 0;

  if (work -> static_type)
    {
      string_append (declp, *mangled + 1);
      *mangled += strlen (*mangled);
      success = 1;
    }
  else
    {
      success = demangle_args (work, mangled, declp);
    }
  return (success);
}

#endif

static int
demangle_template_template_parm (struct work_stuff *work,
                                 const char **mangled, string *tname)
{
  int i;
  int r;
  int need_comma = 0;
  int success = 1;
  string temp;

  string_append (tname, "template <");
  /* get size of template parameter list */
  if (get_count (mangled, &r))
    {
      for (i = 0; i < r; i++)
	{
	  if (need_comma)
	    {
	      string_append (tname, ", ");
	    }

	    /* Z for type parameters */
	    if (**mangled == 'Z')
	      {
		(*mangled)++;
		string_append (tname, "class");
	      }
	      /* z for template parameters */
	    else if (**mangled == 'z')
	      {
		(*mangled)++;
		success =
		  demangle_template_template_parm (work, mangled, tname);
		if (!success)
		  {
		    break;
		  }
	      }
	    else
	      {
		/* temp is initialized in do_type */
		success = do_type (work, mangled, &temp);
		if (success)
		  {
		    string_appends (tname, &temp);
		  }
		string_delete(&temp);
		if (!success)
		  {
		    break;
		  }
	      }
	  need_comma = 1;
	}

    }
  if (tname->p[-1] == '>')
    string_append (tname, " ");
  string_append (tname, "> class");
  return (success);
}

static int
demangle_expression (struct work_stuff *work, const char **mangled,
                     string *s, type_kind_t tk)
{
  int need_operator = 0;
  int success;

  success = 1;
  string_appendn (s, "(", 1);
  (*mangled)++;
  while (success && **mangled != 'W' && **mangled != '\0')
    {
      if (need_operator)
	{
	  size_t i;
	  size_t len;

	  success = 0;

	  len = strlen (*mangled);

	  for (i = 0; i < ARRAY_SIZE (optable); ++i)
	    {
	      size_t l = strlen (optable[i].in);

	      if (l <= len
		  && memcmp (optable[i].in, *mangled, l) == 0)
		{
		  string_appendn (s, " ", 1);
		  string_append (s, optable[i].out);
		  string_appendn (s, " ", 1);
		  success = 1;
		  (*mangled) += l;
		  break;
		}
	    }

	  if (!success)
	    break;
	}
      else
	need_operator = 1;

      success = demangle_template_value_parm (work, mangled, s, tk);
    }

  if (**mangled != 'W')
    success = 0;
  else
    {
      string_appendn (s, ")", 1);
      (*mangled)++;
    }

  return success;
}

static int
demangle_integral_value (struct work_stuff *work,
                         const char **mangled, string *s)
{
  int success;

  if (**mangled == 'E')
    success = demangle_expression (work, mangled, s, tk_integral);
  else if (**mangled == 'Q' || **mangled == 'K')
    success = demangle_qualified (work, mangled, s, 0, 1);
  else
    {
      int value;

      /* By default, we let the number decide whether we shall consume an
	 underscore.  */
      int multidigit_without_leading_underscore = 0;
      int leave_following_underscore = 0;

      success = 0;

      if (**mangled == '_')
        {
	  if (mangled[0][1] == 'm')
	    {
	      /* Since consume_count_with_underscores does not handle the
		 `m'-prefix we must do it here, using consume_count and
		 adjusting underscores: we have to consume the underscore
		 matching the prepended one.  */
	      multidigit_without_leading_underscore = 1;
	      string_appendn (s, "-", 1);
	      (*mangled) += 2;
	    }
	  else
	    {
	      /* Do not consume a following underscore;
	         consume_count_with_underscores will consume what
	         should be consumed.  */
	      leave_following_underscore = 1;
	    }
	}
      else
	{
	  /* Negative numbers are indicated with a leading `m'.  */
	  if (**mangled == 'm')
	  {
	    string_appendn (s, "-", 1);
	    (*mangled)++;
	  }
	  /* Since consume_count_with_underscores does not handle
	     multi-digit numbers that do not start with an underscore,
	     and this number can be an integer template parameter,
	     we have to call consume_count. */
	  multidigit_without_leading_underscore = 1;
	  /* These multi-digit numbers never end on an underscore,
	     so if there is one then don't eat it. */
	  leave_following_underscore = 1;
	}

      /* We must call consume_count if we expect to remove a trailing
	 underscore, since consume_count_with_underscores expects
	 the leading underscore (that we consumed) if it is to handle
	 multi-digit numbers.  */
      if (multidigit_without_leading_underscore)
	value = consume_count (mangled);
      else
	value = consume_count_with_underscores (mangled);

      if (value != -1)
	{
	  char buf[INTBUF_SIZE];
	  sprintf (buf, "%d", value);
	  string_append (s, buf);

	  /* Numbers not otherwise delimited, might have an underscore
	     appended as a delimeter, which we should skip.

	     ??? This used to always remove a following underscore, which
	     is wrong.  If other (arbitrary) cases are followed by an
	     underscore, we need to do something more radical.  */

	  if ((value > 9 || multidigit_without_leading_underscore)
	      && ! leave_following_underscore
	      && **mangled == '_')
	    (*mangled)++;

	  /* All is well.  */
	  success = 1;
	}
      }

  return success;
}

/* Demangle the real value in MANGLED.  */

static int
demangle_real_value (struct work_stuff *work,
                     const char **mangled, string *s)
{
  if (**mangled == 'E')
    return demangle_expression (work, mangled, s, tk_real);

  if (**mangled == 'm')
    {
      string_appendn (s, "-", 1);
      (*mangled)++;
    }
  while (ISDIGIT ((unsigned char)**mangled))
    {
      string_appendn (s, *mangled, 1);
      (*mangled)++;
    }
  if (**mangled == '.') /* fraction */
    {
      string_appendn (s, ".", 1);
      (*mangled)++;
      while (ISDIGIT ((unsigned char)**mangled))
	{
	  string_appendn (s, *mangled, 1);
	  (*mangled)++;
	}
    }
  if (**mangled == 'e') /* exponent */
    {
      string_appendn (s, "e", 1);
      (*mangled)++;
      while (ISDIGIT ((unsigned char)**mangled))
	{
	  string_appendn (s, *mangled, 1);
	  (*mangled)++;
	}
    }

  return 1;
}

static int
demangle_template_value_parm (struct work_stuff *work, const char **mangled,
                              string *s, type_kind_t tk)
{
  int success = 1;

  if (**mangled == 'Y')
    {
      /* The next argument is a template parameter. */
      int idx;

      (*mangled)++;
      idx = consume_count_with_underscores (mangled);
      if (idx == -1
	  || (work->tmpl_argvec && idx >= work->ntmpl_args)
	  || consume_count_with_underscores (mangled) == -1)
	return -1;
      if (work->tmpl_argvec)
	string_append (s, work->tmpl_argvec[idx]);
      else
	string_append_template_idx (s, idx);
    }
  else if (tk == tk_integral)
    success = demangle_integral_value (work, mangled, s);
  else if (tk == tk_char)
    {
      char tmp[2];
      int val;
      if (**mangled == 'm')
	{
	  string_appendn (s, "-", 1);
	  (*mangled)++;
	}
      string_appendn (s, "'", 1);
      val = consume_count(mangled);
      if (val <= 0)
	success = 0;
      else
	{
	  tmp[0] = (char)val;
	  tmp[1] = '\0';
	  string_appendn (s, &tmp[0], 1);
	  string_appendn (s, "'", 1);
	}
    }
  else if (tk == tk_bool)
    {
      int val = consume_count (mangled);
      if (val == 0)
	string_appendn (s, "false", 5);
      else if (val == 1)
	string_appendn (s, "true", 4);
      else
	success = 0;
    }
  else if (tk == tk_real)
    success = demangle_real_value (work, mangled, s);
  else if (tk == tk_pointer || tk == tk_reference)
    {
      if (**mangled == 'Q')
	success = demangle_qualified (work, mangled, s,
				      /*isfuncname=*/0, 
				      /*append=*/1);
      else
	{
	  int symbol_len  = consume_count (mangled);
	  if (symbol_len == -1)
	    return -1;
	  if (symbol_len == 0)
	    string_appendn (s, "0", 1);
	  else
	    {
	      char *p = XNEWVEC (char, symbol_len + 1), *q;
	      strncpy (p, *mangled, symbol_len);
	      p [symbol_len] = '\0';
	      /* We use cplus_demangle here, rather than
		 internal_cplus_demangle, because the name of the entity
		 mangled here does not make use of any of the squangling
		 or type-code information we have built up thus far; it is
		 mangled independently.  */
	      q = cplus_demangle (p, work->options);
	      if (tk == tk_pointer)
		string_appendn (s, "&", 1);
	      /* FIXME: Pointer-to-member constants should get a
		 qualifying class name here.  */
	      if (q)
		{
		  string_append (s, q);
		  free (q);
		}
	      else
		string_append (s, p);
	      free (p);
	    }
	  *mangled += symbol_len;
	}
    }

  return success;
}

/* Demangle the template name in MANGLED.  The full name of the
   template (e.g., S<int>) is placed in TNAME.  The name without the
   template parameters (e.g. S) is placed in TRAWNAME if TRAWNAME is
   non-NULL.  If IS_TYPE is nonzero, this template is a type template,
   not a function template.  If both IS_TYPE and REMEMBER are nonzero,
   the template is remembered in the list of back-referenceable
   types.  */

static int
demangle_template (struct work_stuff *work, const char **mangled,
                   string *tname, string *trawname,
                   int is_type, int remember)
{
  int i;
  int r;
  int need_comma = 0;
  int success = 0;
  int is_java_array = 0;
  string temp;

  (*mangled)++;
  if (is_type)
    {
      /* get template name */
      if (**mangled == 'z')
	{
	  int idx;
	  (*mangled)++;
	  (*mangled)++;

	  idx = consume_count_with_underscores (mangled);
	  if (idx == -1
	      || (work->tmpl_argvec && idx >= work->ntmpl_args)
	      || consume_count_with_underscores (mangled) == -1)
	    return (0);

	  if (work->tmpl_argvec)
	    {
	      string_append (tname, work->tmpl_argvec[idx]);
	      if (trawname)
		string_append (trawname, work->tmpl_argvec[idx]);
	    }
	  else
	    {
	      string_append_template_idx (tname, idx);
	      if (trawname)
		string_append_template_idx (trawname, idx);
	    }
	}
      else
	{
	  if ((r = consume_count (mangled)) <= 0
	      || (int) strlen (*mangled) < r)
	    {
	      return (0);
	    }
	  is_java_array = (work -> options & DMGL_JAVA)
	    && strncmp (*mangled, "JArray1Z", 8) == 0;
	  if (! is_java_array)
	    {
	      string_appendn (tname, *mangled, r);
	    }
	  if (trawname)
	    string_appendn (trawname, *mangled, r);
	  *mangled += r;
	}
    }
  if (!is_java_array)
    string_append (tname, "<");
  /* get size of template parameter list */
  if (!get_count (mangled, &r))
    {
      return (0);
    }
  if (!is_type)
    {
      /* Create an array for saving the template argument values. */
      work->tmpl_argvec = XNEWVEC (char *, r);
      work->ntmpl_args = r;
      for (i = 0; i < r; i++)
	work->tmpl_argvec[i] = 0;
    }
  for (i = 0; i < r; i++)
    {
      if (need_comma)
	{
	  string_append (tname, ", ");
	}
      /* Z for type parameters */
      if (**mangled == 'Z')
	{
	  (*mangled)++;
	  /* temp is initialized in do_type */
	  success = do_type (work, mangled, &temp);
	  if (success)
	    {
	      string_appends (tname, &temp);

	      if (!is_type)
		{
		  /* Save the template argument. */
		  int len = temp.p - temp.b;
		  work->tmpl_argvec[i] = XNEWVEC (char, len + 1);
		  memcpy (work->tmpl_argvec[i], temp.b, len);
		  work->tmpl_argvec[i][len] = '\0';
		}
	    }
	  string_delete(&temp);
	  if (!success)
	    {
	      break;
	    }
	}
      /* z for template parameters */
      else if (**mangled == 'z')
	{
	  int r2;
	  (*mangled)++;
	  success = demangle_template_template_parm (work, mangled, tname);

	  if (success
	      && (r2 = consume_count (mangled)) > 0
	      && (int) strlen (*mangled) >= r2)
	    {
	      string_append (tname, " ");
	      string_appendn (tname, *mangled, r2);
	      if (!is_type)
		{
		  /* Save the template argument. */
		  int len = r2;
		  work->tmpl_argvec[i] = XNEWVEC (char, len + 1);
		  memcpy (work->tmpl_argvec[i], *mangled, len);
		  work->tmpl_argvec[i][len] = '\0';
		}
	      *mangled += r2;
	    }
	  if (!success)
	    {
	      break;
	    }
	}
      else
	{
	  string  param;
	  string* s;

	  /* otherwise, value parameter */

	  /* temp is initialized in do_type */
	  success = do_type (work, mangled, &temp);
	  string_delete(&temp);
	  if (!success)
	    break;

	  if (!is_type)
	    {
	      s = &param;
	      string_init (s);
	    }
	  else
	    s = tname;

	  success = demangle_template_value_parm (work, mangled, s,
						  (type_kind_t) success);

	  if (!success)
	    {
	      if (!is_type)
		string_delete (s);
	      success = 0;
	      break;
	    }

	  if (!is_type)
	    {
	      int len = s->p - s->b;
	      work->tmpl_argvec[i] = XNEWVEC (char, len + 1);
	      memcpy (work->tmpl_argvec[i], s->b, len);
	      work->tmpl_argvec[i][len] = '\0';

	      string_appends (tname, s);
	      string_delete (s);
	    }
	}
      need_comma = 1;
    }
  if (is_java_array)
    {
      string_append (tname, "[]");
    }
  else
    {
      if (tname->p[-1] == '>')
	string_append (tname, " ");
      string_append (tname, ">");
    }

  if (is_type && remember)
    {
      const int bindex = register_Btype (work);
      remember_Btype (work, tname->b, LEN_STRING (tname), bindex);
    }

  /*
    if (work -> static_type)
    {
    string_append (declp, *mangled + 1);
    *mangled += strlen (*mangled);
    success = 1;
    }
    else
    {
    success = demangle_args (work, mangled, declp);
    }
    }
    */
  return (success);
}

static int
arm_pt (struct work_stuff *work, const char *mangled,
        int n, const char **anchor, const char **args)
{
  /* Check if ARM template with "__pt__" in it ("parameterized type") */
  /* Allow HP also here, because HP's cfront compiler follows ARM to some extent */
  if ((ARM_DEMANGLING || HP_DEMANGLING) && (*anchor = strstr (mangled, "__pt__")))
    {
      int len;
      *args = *anchor + 6;
      len = consume_count (args);
      if (len == -1)
	return 0;
      if (*args + len == mangled + n && **args == '_')
	{
	  ++*args;
	  return 1;
	}
    }
  if (AUTO_DEMANGLING || EDG_DEMANGLING)
    {
      if ((*anchor = strstr (mangled, "__tm__"))
          || (*anchor = strstr (mangled, "__ps__"))
          || (*anchor = strstr (mangled, "__pt__")))
        {
          int len;
          *args = *anchor + 6;
          len = consume_count (args);
	  if (len == -1)
	    return 0;
          if (*args + len == mangled + n && **args == '_')
            {
              ++*args;
              return 1;
            }
        }
      else if ((*anchor = strstr (mangled, "__S")))
        {
 	  int len;
 	  *args = *anchor + 3;
 	  len = consume_count (args);
	  if (len == -1)
	    return 0;
 	  if (*args + len == mangled + n && **args == '_')
            {
              ++*args;
 	      return 1;
            }
        }
    }

  return 0;
}

static void
demangle_arm_hp_template (struct work_stuff *work, const char **mangled,
                          int n, string *declp)
{
  const char *p;
  const char *args;
  const char *e = *mangled + n;
  string arg;

  /* Check for HP aCC template spec: classXt1t2 where t1, t2 are
     template args */
  if (HP_DEMANGLING && ((*mangled)[n] == 'X'))
    {
      char *start_spec_args = NULL;
      int hold_options;

      /* First check for and omit template specialization pseudo-arguments,
         such as in "Spec<#1,#1.*>" */
      start_spec_args = strchr (*mangled, '<');
      if (start_spec_args && (start_spec_args - *mangled < n))
        string_appendn (declp, *mangled, start_spec_args - *mangled);
      else
        string_appendn (declp, *mangled, n);
      (*mangled) += n + 1;
      string_init (&arg);
      if (work->temp_start == -1) /* non-recursive call */
        work->temp_start = declp->p - declp->b;

      /* We want to unconditionally demangle parameter types in
	 template parameters.  */
      hold_options = work->options;
      work->options |= DMGL_PARAMS;

      string_append (declp, "<");
      while (1)
        {
          string_delete (&arg);
          switch (**mangled)
            {
              case 'T':
                /* 'T' signals a type parameter */
                (*mangled)++;
                if (!do_type (work, mangled, &arg))
                  goto hpacc_template_args_done;
                break;

              case 'U':
              case 'S':
                /* 'U' or 'S' signals an integral value */
                if (!do_hpacc_template_const_value (work, mangled, &arg))
                  goto hpacc_template_args_done;
                break;

              case 'A':
                /* 'A' signals a named constant expression (literal) */
                if (!do_hpacc_template_literal (work, mangled, &arg))
                  goto hpacc_template_args_done;
                break;

              default:
                /* Today, 1997-09-03, we have only the above types
                   of template parameters */
                /* FIXME: maybe this should fail and return null */
                goto hpacc_template_args_done;
            }
          string_appends (declp, &arg);
         /* Check if we're at the end of template args.
             0 if at end of static member of template class,
             _ if done with template args for a function */
          if ((**mangled == '\000') || (**mangled == '_'))
            break;
          else
            string_append (declp, ",");
        }
    hpacc_template_args_done:
      string_append (declp, ">");
      string_delete (&arg);
      if (**mangled == '_')
        (*mangled)++;
      work->options = hold_options;
      return;
    }
  /* ARM template? (Also handles HP cfront extensions) */
  else if (arm_pt (work, *mangled, n, &p, &args))
    {
      int hold_options;
      string type_str;

      string_init (&arg);
      string_appendn (declp, *mangled, p - *mangled);
      if (work->temp_start == -1)  /* non-recursive call */
	work->temp_start = declp->p - declp->b;

      /* We want to unconditionally demangle parameter types in
	 template parameters.  */
      hold_options = work->options;
      work->options |= DMGL_PARAMS;

      string_append (declp, "<");
      /* should do error checking here */
      while (args < e) {
	string_delete (&arg);

	/* Check for type or literal here */
	switch (*args)
	  {
	    /* HP cfront extensions to ARM for template args */
	    /* spec: Xt1Lv1 where t1 is a type, v1 is a literal value */
	    /* FIXME: We handle only numeric literals for HP cfront */
          case 'X':
            /* A typed constant value follows */
            args++;
            if (!do_type (work, &args, &type_str))
	      goto cfront_template_args_done;
            string_append (&arg, "(");
            string_appends (&arg, &type_str);
            string_delete (&type_str);
            string_append (&arg, ")");
            if (*args != 'L')
              goto cfront_template_args_done;
            args++;
            /* Now snarf a literal value following 'L' */
            if (!snarf_numeric_literal (&args, &arg))
	      goto cfront_template_args_done;
            break;

          case 'L':
            /* Snarf a literal following 'L' */
            args++;
            if (!snarf_numeric_literal (&args, &arg))
	      goto cfront_template_args_done;
            break;
          default:
            /* Not handling other HP cfront stuff */
            {
              const char* old_args = args;
              if (!do_type (work, &args, &arg))
                goto cfront_template_args_done;

              /* Fail if we didn't make any progress: prevent infinite loop. */
              if (args == old_args)
		{
		  work->options = hold_options;
		  return;
		}
            }
	  }
	string_appends (declp, &arg);
	string_append (declp, ",");
      }
    cfront_template_args_done:
      string_delete (&arg);
      if (args >= e)
	--declp->p; /* remove extra comma */
      string_append (declp, ">");
      work->options = hold_options;
    }
  else if (n>10 && strncmp (*mangled, "_GLOBAL_", 8) == 0
	   && (*mangled)[9] == 'N'
	   && (*mangled)[8] == (*mangled)[10]
	   && strchr (cplus_markers, (*mangled)[8]))
    {
      /* A member of the anonymous namespace.  */
      string_append (declp, "{anonymous}");
    }
  else
    {
      if (work->temp_start == -1) /* non-recursive call only */
	work->temp_start = 0;     /* disable in recursive calls */
      string_appendn (declp, *mangled, n);
    }
  *mangled += n;
}

/* Extract a class name, possibly a template with arguments, from the
   mangled string; qualifiers, local class indicators, etc. have
   already been dealt with */

static int
demangle_class_name (struct work_stuff *work, const char **mangled,
                     string *declp)
{
  int n;
  int success = 0;

  n = consume_count (mangled);
  if (n == -1)
    return 0;
  if ((int) strlen (*mangled) >= n)
    {
      demangle_arm_hp_template (work, mangled, n, declp);
      success = 1;
    }

  return (success);
}

/*

LOCAL FUNCTION

	demangle_class -- demangle a mangled class sequence

SYNOPSIS

	static int
	demangle_class (struct work_stuff *work, const char **mangled,
			strint *declp)

DESCRIPTION

	DECLP points to the buffer into which demangling is being done.

	*MANGLED points to the current token to be demangled.  On input,
	it points to a mangled class (I.E. "3foo", "13verylongclass", etc.)
	On exit, it points to the next token after the mangled class on
	success, or the first unconsumed token on failure.

	If the CONSTRUCTOR or DESTRUCTOR flags are set in WORK, then
	we are demangling a constructor or destructor.  In this case
	we prepend "class::class" or "class::~class" to DECLP.

	Otherwise, we prepend "class::" to the current DECLP.

	Reset the constructor/destructor flags once they have been
	"consumed".  This allows demangle_class to be called later during
	the same demangling, to do normal class demangling.

	Returns 1 if demangling is successful, 0 otherwise.

*/

static int
demangle_class (struct work_stuff *work, const char **mangled, string *declp)
{
  int success = 0;
  int btype;
  string class_name;
  char *save_class_name_end = 0;

  string_init (&class_name);
  btype = register_Btype (work);
  if (demangle_class_name (work, mangled, &class_name))
    {
      save_class_name_end = class_name.p;
      if ((work->constructor & 1) || (work->destructor & 1))
	{
          /* adjust so we don't include template args */
          if (work->temp_start && (work->temp_start != -1))
            {
              class_name.p = class_name.b + work->temp_start;
            }
	  string_prepends (declp, &class_name);
	  if (work -> destructor & 1)
	    {
	      string_prepend (declp, "~");
              work -> destructor -= 1;
	    }
	  else
	    {
	      work -> constructor -= 1;
	    }
	}
      class_name.p = save_class_name_end;
      remember_Ktype (work, class_name.b, LEN_STRING(&class_name));
      remember_Btype (work, class_name.b, LEN_STRING(&class_name), btype);
      string_prepend (declp, SCOPE_STRING (work));
      string_prepends (declp, &class_name);
      success = 1;
    }
  string_delete (&class_name);
  return (success);
}


/* Called when there's a "__" in the mangled name, with `scan' pointing to
   the rightmost guess.

   Find the correct "__"-sequence where the function name ends and the
   signature starts, which is ambiguous with GNU mangling.
   Call demangle_signature here, so we can make sure we found the right
   one; *mangled will be consumed so caller will not make further calls to
   demangle_signature.  */

static int
iterate_demangle_function (struct work_stuff *work, const char **mangled,
                           string *declp, const char *scan)
{
  const char *mangle_init = *mangled;
  int success = 0;
  string decl_init;
  struct work_stuff work_init;

  if (*(scan + 2) == '\0')
    return 0;

  /* Do not iterate for some demangling modes, or if there's only one
     "__"-sequence.  This is the normal case.  */
  if (ARM_DEMANGLING || LUCID_DEMANGLING || HP_DEMANGLING || EDG_DEMANGLING
      || strstr (scan + 2, "__") == NULL)
    return demangle_function_name (work, mangled, declp, scan);

  /* Save state so we can restart if the guess at the correct "__" was
     wrong.  */
  string_init (&decl_init);
  string_appends (&decl_init, declp);
  memset (&work_init, 0, sizeof work_init);
  work_stuff_copy_to_from (&work_init, work);

  /* Iterate over occurrences of __, allowing names and types to have a
     "__" sequence in them.  We must start with the first (not the last)
     occurrence, since "__" most often occur between independent mangled
     parts, hence starting at the last occurence inside a signature
     might get us a "successful" demangling of the signature.  */

  while (scan[2])
    {
      if (demangle_function_name (work, mangled, declp, scan))
	{
	  success = demangle_signature (work, mangled, declp);
	  if (success)
	    break;
	}

      /* Reset demangle state for the next round.  */
      *mangled = mangle_init;
      string_clear (declp);
      string_appends (declp, &decl_init);
      work_stuff_copy_to_from (work, &work_init);

      /* Leave this underscore-sequence.  */
      scan += 2;

      /* Scan for the next "__" sequence.  */
      while (*scan && (scan[0] != '_' || scan[1] != '_'))
	scan++;

      /* Move to last "__" in this sequence.  */
      while (*scan && *scan == '_')
	scan++;
      scan -= 2;
    }

  /* Delete saved state.  */
  delete_work_stuff (&work_init);
  string_delete (&decl_init);

  return success;
}

/*

LOCAL FUNCTION

	demangle_prefix -- consume the mangled name prefix and find signature

SYNOPSIS

	static int
	demangle_prefix (struct work_stuff *work, const char **mangled,
			 string *declp);

DESCRIPTION

	Consume and demangle the prefix of the mangled name.
	While processing the function name root, arrange to call
	demangle_signature if the root is ambiguous.

	DECLP points to the string buffer into which demangled output is
	placed.  On entry, the buffer is empty.  On exit it contains
	the root function name, the demangled operator name, or in some
	special cases either nothing or the completely demangled result.

	MANGLED points to the current pointer into the mangled name.  As each
	token of the mangled name is consumed, it is updated.  Upon entry
	the current mangled name pointer points to the first character of
	the mangled name.  Upon exit, it should point to the first character
	of the signature if demangling was successful, or to the first
	unconsumed character if demangling of the prefix was unsuccessful.

	Returns 1 on success, 0 otherwise.
 */

static int
demangle_prefix (struct work_stuff *work, const char **mangled,
                 string *declp)
{
  int success = 1;
  const char *scan;
  int i;

  if (strlen(*mangled) > 6
      && (strncmp(*mangled, "_imp__", 6) == 0
          || strncmp(*mangled, "__imp_", 6) == 0))
    {
      /* it's a symbol imported from a PE dynamic library. Check for both
         new style prefix _imp__ and legacy __imp_ used by older versions
	 of dlltool. */
      (*mangled) += 6;
      work->dllimported = 1;
    }
  else if (strlen(*mangled) >= 11 && strncmp(*mangled, "_GLOBAL_", 8) == 0)
    {
      char *marker = strchr (cplus_markers, (*mangled)[8]);
      if (marker != NULL && *marker == (*mangled)[10])
	{
	  if ((*mangled)[9] == 'D')
	    {
	      /* it's a GNU global destructor to be executed at program exit */
	      (*mangled) += 11;
	      work->destructor = 2;
	      if (gnu_special (work, mangled, declp))
		return success;
	    }
	  else if ((*mangled)[9] == 'I')
	    {
	      /* it's a GNU global constructor to be executed at program init */
	      (*mangled) += 11;
	      work->constructor = 2;
	      if (gnu_special (work, mangled, declp))
		return success;
	    }
	}
    }
  else if ((ARM_DEMANGLING || HP_DEMANGLING || EDG_DEMANGLING) && strncmp(*mangled, "__std__", 7) == 0)
    {
      /* it's a ARM global destructor to be executed at program exit */
      (*mangled) += 7;
      work->destructor = 2;
    }
  else if ((ARM_DEMANGLING || HP_DEMANGLING || EDG_DEMANGLING) && strncmp(*mangled, "__sti__", 7) == 0)
    {
      /* it's a ARM global constructor to be executed at program initial */
      (*mangled) += 7;
      work->constructor = 2;
    }

  /*  This block of code is a reduction in strength time optimization
      of:
      scan = strstr (*mangled, "__"); */

  {
    scan = *mangled;

    do {
      scan = strchr (scan, '_');
    } while (scan != NULL && *++scan != '_');

    if (scan != NULL) --scan;
  }

  if (scan != NULL)
    {
      /* We found a sequence of two or more '_', ensure that we start at
	 the last pair in the sequence.  */
      i = strspn (scan, "_");
      if (i > 2)
	{
	  scan += (i - 2);
	}
    }

  if (scan == NULL)
    {
      success = 0;
    }
  else if (work -> static_type)
    {
      if (!ISDIGIT ((unsigned char)scan[0]) && (scan[0] != 't'))
	{
	  success = 0;
	}
    }
  else if ((scan == *mangled)
	   && (ISDIGIT ((unsigned char)scan[2]) || (scan[2] == 'Q')
	       || (scan[2] == 't') || (scan[2] == 'K') || (scan[2] == 'H')))
    {
      /* The ARM says nothing about the mangling of local variables.
	 But cfront mangles local variables by prepending __<nesting_level>
	 to them. As an extension to ARM demangling we handle this case.  */
      if ((LUCID_DEMANGLING || ARM_DEMANGLING || HP_DEMANGLING)
	  && ISDIGIT ((unsigned char)scan[2]))
	{
	  *mangled = scan + 2;
	  consume_count (mangled);
	  string_append (declp, *mangled);
	  *mangled += strlen (*mangled);
	  success = 1;
	}
      else
	{
	  /* A GNU style constructor starts with __[0-9Qt].  But cfront uses
	     names like __Q2_3foo3bar for nested type names.  So don't accept
	     this style of constructor for cfront demangling.  A GNU
	     style member-template constructor starts with 'H'. */
	  if (!(LUCID_DEMANGLING || ARM_DEMANGLING || HP_DEMANGLING || EDG_DEMANGLING))
	    work -> constructor += 1;
	  *mangled = scan + 2;
	}
    }
  else if (ARM_DEMANGLING && scan[2] == 'p' && scan[3] == 't')
    {
      /* Cfront-style parameterized type.  Handled later as a signature. */
      success = 1;

      /* ARM template? */
      demangle_arm_hp_template (work, mangled, strlen (*mangled), declp);
    }
  else if (EDG_DEMANGLING && ((scan[2] == 't' && scan[3] == 'm')
                              || (scan[2] == 'p' && scan[3] == 's')
                              || (scan[2] == 'p' && scan[3] == 't')))
    {
      /* EDG-style parameterized type.  Handled later as a signature. */
      success = 1;

      /* EDG template? */
      demangle_arm_hp_template (work, mangled, strlen (*mangled), declp);
    }
  else if ((scan == *mangled) && !ISDIGIT ((unsigned char)scan[2])
	   && (scan[2] != 't'))
    {
      /* Mangled name starts with "__".  Skip over any leading '_' characters,
	 then find the next "__" that separates the prefix from the signature.
	 */
      if (!(ARM_DEMANGLING || LUCID_DEMANGLING || HP_DEMANGLING || EDG_DEMANGLING)
	  || (arm_special (mangled, declp) == 0))
	{
	  while (*scan == '_')
	    {
	      scan++;
	    }
	  if ((scan = strstr (scan, "__")) == NULL || (*(scan + 2) == '\0'))
	    {
	      /* No separator (I.E. "__not_mangled"), or empty signature
		 (I.E. "__not_mangled_either__") */
	      success = 0;
	    }
	  else
	    return iterate_demangle_function (work, mangled, declp, scan);
	}
    }
  else if (*(scan + 2) != '\0')
    {
      /* Mangled name does not start with "__" but does have one somewhere
	 in there with non empty stuff after it.  Looks like a global
	 function name.  Iterate over all "__":s until the right
	 one is found.  */
      return iterate_demangle_function (work, mangled, declp, scan);
    }
  else
    {
      /* Doesn't look like a mangled name */
      success = 0;
    }

  if (!success && (work->constructor == 2 || work->destructor == 2))
    {
      string_append (declp, *mangled);
      *mangled += strlen (*mangled);
      success = 1;
    }
  return (success);
}

/*

LOCAL FUNCTION

	gnu_special -- special handling of gnu mangled strings

SYNOPSIS

	static int
	gnu_special (struct work_stuff *work, const char **mangled,
		     string *declp);


DESCRIPTION

	Process some special GNU style mangling forms that don't fit
	the normal pattern.  For example:

		_$_3foo		(destructor for class foo)
		_vt$foo		(foo virtual table)
		_vt$foo$bar	(foo::bar virtual table)
		__vt_foo	(foo virtual table, new style with thunks)
		_3foo$varname	(static data member)
		_Q22rs2tu$vw	(static data member)
		__t6vector1Zii	(constructor with template)
		__thunk_4__$_7ostream (virtual function thunk)
 */

static int
gnu_special (struct work_stuff *work, const char **mangled, string *declp)
{
  int n;
  int success = 1;
  const char *p;

  if ((*mangled)[0] == '_'
      && strchr (cplus_markers, (*mangled)[1]) != NULL
      && (*mangled)[2] == '_')
    {
      /* Found a GNU style destructor, get past "_<CPLUS_MARKER>_" */
      (*mangled) += 3;
      work -> destructor += 1;
    }
  else if ((*mangled)[0] == '_'
	   && (((*mangled)[1] == '_'
		&& (*mangled)[2] == 'v'
		&& (*mangled)[3] == 't'
		&& (*mangled)[4] == '_')
	       || ((*mangled)[1] == 'v'
		   && (*mangled)[2] == 't'
		   && strchr (cplus_markers, (*mangled)[3]) != NULL)))
    {
      /* Found a GNU style virtual table, get past "_vt<CPLUS_MARKER>"
         and create the decl.  Note that we consume the entire mangled
	 input string, which means that demangle_signature has no work
	 to do.  */
      if ((*mangled)[2] == 'v')
	(*mangled) += 5; /* New style, with thunks: "__vt_" */
      else
	(*mangled) += 4; /* Old style, no thunks: "_vt<CPLUS_MARKER>" */
      while (**mangled != '\0')
	{
	  switch (**mangled)
	    {
	    case 'Q':
	    case 'K':
	      success = demangle_qualified (work, mangled, declp, 0, 1);
	      break;
	    case 't':
	      success = demangle_template (work, mangled, declp, 0, 1,
					   1);
	      break;
	    default:
	      if (ISDIGIT((unsigned char)*mangled[0]))
		{
		  n = consume_count(mangled);
		  /* We may be seeing a too-large size, or else a
		     ".<digits>" indicating a static local symbol.  In
		     any case, declare victory and move on; *don't* try
		     to use n to allocate.  */
		  if (n > (int) strlen (*mangled))
		    {
		      success = 1;
		      break;
		    }
		}
	      else
		{
		  n = strcspn (*mangled, cplus_markers);
		}
	      string_appendn (declp, *mangled, n);
	      (*mangled) += n;
	    }

	  p = strpbrk (*mangled, cplus_markers);
	  if (success && ((p == NULL) || (p == *mangled)))
	    {
	      if (p != NULL)
		{
		  string_append (declp, SCOPE_STRING (work));
		  (*mangled)++;
		}
	    }
	  else
	    {
	      success = 0;
	      break;
	    }
	}
      if (success)
	string_append (declp, " virtual table");
    }
  else if ((*mangled)[0] == '_'
	   && (strchr("0123456789Qt", (*mangled)[1]) != NULL)
	   && (p = strpbrk (*mangled, cplus_markers)) != NULL)
    {
      /* static data member, "_3foo$varname" for example */
      (*mangled)++;
      switch (**mangled)
	{
	case 'Q':
	case 'K':
	  success = demangle_qualified (work, mangled, declp, 0, 1);
	  break;
	case 't':
	  success = demangle_template (work, mangled, declp, 0, 1, 1);
	  break;
	default:
	  n = consume_count (mangled);
	  if (n < 0 || n > (long) strlen (*mangled))
	    {
	      success = 0;
	      break;
	    }

	  if (n > 10 && strncmp (*mangled, "_GLOBAL_", 8) == 0
	      && (*mangled)[9] == 'N'
	      && (*mangled)[8] == (*mangled)[10]
	      && strchr (cplus_markers, (*mangled)[8]))
	    {
	      /* A member of the anonymous namespace.  There's information
		 about what identifier or filename it was keyed to, but
		 it's just there to make the mangled name unique; we just
		 step over it.  */
	      string_append (declp, "{anonymous}");
	      (*mangled) += n;

	      /* Now p points to the marker before the N, so we need to
		 update it to the first marker after what we consumed.  */
	      p = strpbrk (*mangled, cplus_markers);
	      break;
	    }

	  string_appendn (declp, *mangled, n);
	  (*mangled) += n;
	}
      if (success && (p == *mangled))
	{
	  /* Consumed everything up to the cplus_marker, append the
	     variable name.  */
	  (*mangled)++;
	  string_append (declp, SCOPE_STRING (work));
	  n = strlen (*mangled);
	  string_appendn (declp, *mangled, n);
	  (*mangled) += n;
	}
      else
	{
	  success = 0;
	}
    }
  else if (strncmp (*mangled, "__thunk_", 8) == 0)
    {
      int delta;

      (*mangled) += 8;
      delta = consume_count (mangled);
      if (delta == -1)
	success = 0;
      else
	{
	  char *method = internal_cplus_demangle (work, ++*mangled);

	  if (method)
	    {
	      char buf[50];
	      sprintf (buf, "virtual function thunk (delta:%d) for ", -delta);
	      string_append (declp, buf);
	      string_append (declp, method);
	      free (method);
	      n = strlen (*mangled);
	      (*mangled) += n;
	    }
	  else
	    {
	      success = 0;
	    }
	}
    }
  else if (strncmp (*mangled, "__t", 3) == 0
	   && ((*mangled)[3] == 'i' || (*mangled)[3] == 'f'))
    {
      p = (*mangled)[3] == 'i' ? " type_info node" : " type_info function";
      (*mangled) += 4;
      switch (**mangled)
	{
	case 'Q':
	case 'K':
	  success = demangle_qualified (work, mangled, declp, 0, 1);
	  break;
	case 't':
	  success = demangle_template (work, mangled, declp, 0, 1, 1);
	  break;
	default:
	  success = do_type (work, mangled, declp);
	  break;
	}
      if (success && **mangled != '\0')
	success = 0;
      if (success)
	string_append (declp, p);
    }
  else
    {
      success = 0;
    }
  return (success);
}

static void
recursively_demangle(struct work_stuff *work, const char **mangled,
                     string *result, int namelength)
{
  char * recurse = (char *)NULL;
  char * recurse_dem = (char *)NULL;

  recurse = XNEWVEC (char, namelength + 1);
  memcpy (recurse, *mangled, namelength);
  recurse[namelength] = '\000';

  recurse_dem = cplus_demangle (recurse, work->options);

  if (recurse_dem)
    {
      string_append (result, recurse_dem);
      free (recurse_dem);
    }
  else
    {
      string_appendn (result, *mangled, namelength);
    }
  free (recurse);
  *mangled += namelength;
}

/*

LOCAL FUNCTION

	arm_special -- special handling of ARM/lucid mangled strings

SYNOPSIS

	static int
	arm_special (const char **mangled,
		     string *declp);


DESCRIPTION

	Process some special ARM style mangling forms that don't fit
	the normal pattern.  For example:

		__vtbl__3foo		(foo virtual table)
		__vtbl__3foo__3bar	(bar::foo virtual table)

 */

static int
arm_special (const char **mangled, string *declp)
{
  int n;
  int success = 1;
  const char *scan;

  if (strncmp (*mangled, ARM_VTABLE_STRING, ARM_VTABLE_STRLEN) == 0)
    {
      /* Found a ARM style virtual table, get past ARM_VTABLE_STRING
         and create the decl.  Note that we consume the entire mangled
	 input string, which means that demangle_signature has no work
	 to do.  */
      scan = *mangled + ARM_VTABLE_STRLEN;
      while (*scan != '\0')        /* first check it can be demangled */
        {
          n = consume_count (&scan);
          if (n == -1)
	    {
	      return (0);           /* no good */
	    }
          scan += n;
          if (scan[0] == '_' && scan[1] == '_')
	    {
	      scan += 2;
	    }
        }
      (*mangled) += ARM_VTABLE_STRLEN;
      while (**mangled != '\0')
	{
	  n = consume_count (mangled);
          if (n == -1
	      || n > (long) strlen (*mangled))
	    return 0;
	  string_prependn (declp, *mangled, n);
	  (*mangled) += n;
	  if ((*mangled)[0] == '_' && (*mangled)[1] == '_')
	    {
	      string_prepend (declp, "::");
	      (*mangled) += 2;
	    }
	}
      string_append (declp, " virtual table");
    }
  else
    {
      success = 0;
    }
  return (success);
}

/*

LOCAL FUNCTION

	demangle_qualified -- demangle 'Q' qualified name strings

SYNOPSIS

	static int
	demangle_qualified (struct work_stuff *, const char *mangled,
			    string *result, int isfuncname, int append);

DESCRIPTION

	Demangle a qualified name, such as "Q25Outer5Inner" which is
	the mangled form of "Outer::Inner".  The demangled output is
	prepended or appended to the result string according to the
	state of the append flag.

	If isfuncname is nonzero, then the qualified name we are building
	is going to be used as a member function name, so if it is a
	constructor or destructor function, append an appropriate
	constructor or destructor name.  I.E. for the above example,
	the result for use as a constructor is "Outer::Inner::Inner"
	and the result for use as a destructor is "Outer::Inner::~Inner".

BUGS

	Numeric conversion is ASCII dependent (FIXME).

 */

static int
demangle_qualified (struct work_stuff *work, const char **mangled,
                    string *result, int isfuncname, int append)
{
  int qualifiers = 0;
  int success = 1;
  char num[2];
  string temp;
  string last_name;
  int bindex = register_Btype (work);

  /* We only make use of ISFUNCNAME if the entity is a constructor or
     destructor.  */
  isfuncname = (isfuncname
		&& ((work->constructor & 1) || (work->destructor & 1)));

  string_init (&temp);
  string_init (&last_name);

  if ((*mangled)[0] == 'K')
    {
    /* Squangling qualified name reuse */
      int idx;
      (*mangled)++;
      idx = consume_count_with_underscores (mangled);
      if (idx == -1 || idx >= work -> numk)
        success = 0;
      else
        string_append (&temp, work -> ktypevec[idx]);
    }
  else
    switch ((*mangled)[1])
    {
    case '_':
      /* GNU mangled name with more than 9 classes.  The count is preceded
	 by an underscore (to distinguish it from the <= 9 case) and followed
	 by an underscore.  */
      (*mangled)++;
      qualifiers = consume_count_with_underscores (mangled);
      if (qualifiers == -1)
	success = 0;
      break;

    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      /* The count is in a single digit.  */
      num[0] = (*mangled)[1];
      num[1] = '\0';
      qualifiers = atoi (num);

      /* If there is an underscore after the digit, skip it.  This is
	 said to be for ARM-qualified names, but the ARM makes no
	 mention of such an underscore.  Perhaps cfront uses one.  */
      if ((*mangled)[2] == '_')
	{
	  (*mangled)++;
	}
      (*mangled) += 2;
      break;

    case '0':
    default:
      success = 0;
    }

  if (!success)
    return success;

  /* Pick off the names and collect them in the temp buffer in the order
     in which they are found, separated by '::'.  */

  while (qualifiers-- > 0)
    {
      int remember_K = 1;
      string_clear (&last_name);

      if (*mangled[0] == '_')
	(*mangled)++;

      if (*mangled[0] == 't')
	{
	  /* Here we always append to TEMP since we will want to use
	     the template name without the template parameters as a
	     constructor or destructor name.  The appropriate
	     (parameter-less) value is returned by demangle_template
	     in LAST_NAME.  We do not remember the template type here,
	     in order to match the G++ mangling algorithm.  */
	  success = demangle_template(work, mangled, &temp,
				      &last_name, 1, 0);
	  if (!success)
	    break;
	}
      else if (*mangled[0] == 'K')
	{
          int idx;
          (*mangled)++;
          idx = consume_count_with_underscores (mangled);
          if (idx == -1 || idx >= work->numk)
            success = 0;
          else
            string_append (&temp, work->ktypevec[idx]);
          remember_K = 0;

	  if (!success) break;
	}
      else
	{
	  if (EDG_DEMANGLING)
            {
	      int namelength;
 	      /* Now recursively demangle the qualifier
 	       * This is necessary to deal with templates in
 	       * mangling styles like EDG */
	      namelength = consume_count (mangled);
	      if (namelength == -1)
		{
		  success = 0;
		  break;
		}
 	      recursively_demangle(work, mangled, &temp, namelength);
            }
          else
            {
              string_delete (&last_name);
              success = do_type (work, mangled, &last_name);
              if (!success)
                break;
              string_appends (&temp, &last_name);
            }
	}

      if (remember_K)
	remember_Ktype (work, temp.b, LEN_STRING (&temp));

      if (qualifiers > 0)
	string_append (&temp, SCOPE_STRING (work));
    }

  remember_Btype (work, temp.b, LEN_STRING (&temp), bindex);

  /* If we are using the result as a function name, we need to append
     the appropriate '::' separated constructor or destructor name.
     We do this here because this is the most convenient place, where
     we already have a pointer to the name and the length of the name.  */

  if (isfuncname)
    {
      string_append (&temp, SCOPE_STRING (work));
      if (work -> destructor & 1)
	string_append (&temp, "~");
      string_appends (&temp, &last_name);
    }

  /* Now either prepend the temp buffer to the result, or append it,
     depending upon the state of the append flag.  */

  if (append)
    string_appends (result, &temp);
  else
    {
      if (!STRING_EMPTY (result))
	string_append (&temp, SCOPE_STRING (work));
      string_prepends (result, &temp);
    }

  string_delete (&last_name);
  string_delete (&temp);
  return (success);
}

/*

LOCAL FUNCTION

	get_count -- convert an ascii count to integer, consuming tokens

SYNOPSIS

	static int
	get_count (const char **type, int *count)

DESCRIPTION

	Assume that *type points at a count in a mangled name; set
	*count to its value, and set *type to the next character after
	the count.  There are some weird rules in effect here.

	If *type does not point at a string of digits, return zero.

	If *type points at a string of digits followed by an
	underscore, set *count to their value as an integer, advance
	*type to point *after the underscore, and return 1.

	If *type points at a string of digits not followed by an
	underscore, consume only the first digit.  Set *count to its
	value as an integer, leave *type pointing after that digit,
	and return 1.

        The excuse for this odd behavior: in the ARM and HP demangling
        styles, a type can be followed by a repeat count of the form
        `Nxy', where:

        `x' is a single digit specifying how many additional copies
            of the type to append to the argument list, and

        `y' is one or more digits, specifying the zero-based index of
            the first repeated argument in the list.  Yes, as you're
            unmangling the name you can figure this out yourself, but
            it's there anyway.

        So, for example, in `bar__3fooFPiN51', the first argument is a
        pointer to an integer (`Pi'), and then the next five arguments
        are the same (`N5'), and the first repeat is the function's
        second argument (`1').
*/

static int
get_count (const char **type, int *count)
{
  const char *p;
  int n;

  if (!ISDIGIT ((unsigned char)**type))
    return (0);
  else
    {
      *count = **type - '0';
      (*type)++;
      if (ISDIGIT ((unsigned char)**type))
	{
	  p = *type;
	  n = *count;
	  do
	    {
	      n *= 10;
	      n += *p - '0';
	      p++;
	    }
	  while (ISDIGIT ((unsigned char)*p));
	  if (*p == '_')
	    {
	      *type = p + 1;
	      *count = n;
	    }
	}
    }
  return (1);
}

/* RESULT will be initialised here; it will be freed on failure.  The
   value returned is really a type_kind_t.  */

static int
do_type (struct work_stuff *work, const char **mangled, string *result)
{
  int n;
  int done;
  int success;
  string decl;
  const char *remembered_type;
  int type_quals;
  type_kind_t tk = tk_none;

  string_init (&decl);
  string_init (result);

  done = 0;
  success = 1;
  while (success && !done)
    {
      int member;
      switch (**mangled)
	{

	  /* A pointer type */
	case 'P':
	case 'p':
	  (*mangled)++;
	  if (! (work -> options & DMGL_JAVA))
	    string_prepend (&decl, "*");
	  if (tk == tk_none)
	    tk = tk_pointer;
	  break;

	  /* A reference type */
	case 'R':
	  (*mangled)++;
	  string_prepend (&decl, "&");
	  if (tk == tk_none)
	    tk = tk_reference;
	  break;

	  /* An array */
	case 'A':
	  {
	    ++(*mangled);
	    if (!STRING_EMPTY (&decl)
		&& (decl.b[0] == '*' || decl.b[0] == '&'))
	      {
		string_prepend (&decl, "(");
		string_append (&decl, ")");
	      }
	    string_append (&decl, "[");
	    if (**mangled != '_')
	      success = demangle_template_value_parm (work, mangled, &decl,
						      tk_integral);
	    if (**mangled == '_')
	      ++(*mangled);
	    string_append (&decl, "]");
	    break;
	  }

	/* A back reference to a previously seen type */
	case 'T':
	  (*mangled)++;
	  if (!get_count (mangled, &n) || n >= work -> ntypes)
	    {
	      success = 0;
	    }
	  else
	    {
	      remembered_type = work -> typevec[n];
	      mangled = &remembered_type;
	    }
	  break;

	  /* A function */
	case 'F':
	  (*mangled)++;
	    if (!STRING_EMPTY (&decl)
		&& (decl.b[0] == '*' || decl.b[0] == '&'))
	    {
	      string_prepend (&decl, "(");
	      string_append (&decl, ")");
	    }
	  /* After picking off the function args, we expect to either find the
	     function return type (preceded by an '_') or the end of the
	     string.  */
	  if (!demangle_nested_args (work, mangled, &decl)
	      || (**mangled != '_' && **mangled != '\0'))
	    {
	      success = 0;
	      break;
	    }
	  if (success && (**mangled == '_'))
	    (*mangled)++;
	  break;

	case 'M':
	case 'O':
	  {
	    type_quals = TYPE_UNQUALIFIED;

	    member = **mangled == 'M';
	    (*mangled)++;

	    string_append (&decl, ")");

	    /* We don't need to prepend `::' for a qualified name;
	       demangle_qualified will do that for us.  */
	    if (**mangled != 'Q')
	      string_prepend (&decl, SCOPE_STRING (work));

	    if (ISDIGIT ((unsigned char)**mangled))
	      {
		n = consume_count (mangled);
		if (n == -1
		    || (int) strlen (*mangled) < n)
		  {
		    success = 0;
		    break;
		  }
		string_prependn (&decl, *mangled, n);
		*mangled += n;
	      }
	    else if (**mangled == 'X' || **mangled == 'Y')
	      {
		string temp;
		do_type (work, mangled, &temp);
		string_prepends (&decl, &temp);
		string_delete (&temp);
	      }
	    else if (**mangled == 't')
	      {
		string temp;
		string_init (&temp);
		success = demangle_template (work, mangled, &temp,
					     NULL, 1, 1);
		if (success)
		  {
		    string_prependn (&decl, temp.b, temp.p - temp.b);
		    string_delete (&temp);
		  }
		else
		  break;
	      }
	    else if (**mangled == 'Q')
	      {
		success = demangle_qualified (work, mangled, &decl,
					      /*isfuncnam=*/0, 
					      /*append=*/0);
		if (!success)
		  break;
	      }
	    else
	      {
		success = 0;
		break;
	      }

	    string_prepend (&decl, "(");
	    if (member)
	      {
		switch (**mangled)
		  {
		  case 'C':
		  case 'V':
		  case 'u':
		    type_quals |= code_for_qualifier (**mangled);
		    (*mangled)++;
		    break;

		  default:
		    break;
		  }

		if (*(*mangled)++ != 'F')
		  {
		    success = 0;
		    break;
		  }
	      }
	    if ((member && !demangle_nested_args (work, mangled, &decl))
		|| **mangled != '_')
	      {
		success = 0;
		break;
	      }
	    (*mangled)++;
	    if (! PRINT_ANSI_QUALIFIERS)
	      {
		break;
	      }
	    if (type_quals != TYPE_UNQUALIFIED)
	      {
		APPEND_BLANK (&decl);
		string_append (&decl, qualifier_string (type_quals));
	      }
	    break;
	  }
        case 'G':
	  (*mangled)++;
	  break;

	case 'C':
	case 'V':
	case 'u':
	  if (PRINT_ANSI_QUALIFIERS)
	    {
	      if (!STRING_EMPTY (&decl))
		string_prepend (&decl, " ");

	      string_prepend (&decl, demangle_qualifier (**mangled));
	    }
	  (*mangled)++;
	  break;
	  /*
	    }
	    */

	  /* fall through */
	default:
	  done = 1;
	  break;
	}
    }

  if (success) switch (**mangled)
    {
      /* A qualified name, such as "Outer::Inner".  */
    case 'Q':
    case 'K':
      {
        success = demangle_qualified (work, mangled, result, 0, 1);
        break;
      }

    /* A back reference to a previously seen squangled type */
    case 'B':
      (*mangled)++;
      if (!get_count (mangled, &n) || n >= work -> numb)
	success = 0;
      else
	string_append (result, work->btypevec[n]);
      break;

    case 'X':
    case 'Y':
      /* A template parm.  We substitute the corresponding argument. */
      {
	int idx;

	(*mangled)++;
	idx = consume_count_with_underscores (mangled);

	if (idx == -1
	    || (work->tmpl_argvec && idx >= work->ntmpl_args)
	    || consume_count_with_underscores (mangled) == -1)
	  {
	    success = 0;
	    break;
	  }

	if (work->tmpl_argvec)
	  string_append (result, work->tmpl_argvec[idx]);
	else
	  string_append_template_idx (result, idx);

	success = 1;
      }
    break;

    default:
      success = demangle_fund_type (work, mangled, result);
      if (tk == tk_none)
	tk = (type_kind_t) success;
      break;
    }

  if (success)
    {
      if (!STRING_EMPTY (&decl))
	{
	  string_append (result, " ");
	  string_appends (result, &decl);
	}
    }
  else
    string_delete (result);
  string_delete (&decl);

  if (success)
    /* Assume an integral type, if we're not sure.  */
    return (int) ((tk == tk_none) ? tk_integral : tk);
  else
    return 0;
}

/* Given a pointer to a type string that represents a fundamental type
   argument (int, long, unsigned int, etc) in TYPE, a pointer to the
   string in which the demangled output is being built in RESULT, and
   the WORK structure, decode the types and add them to the result.

   For example:

   	"Ci"	=>	"const int"
	"Sl"	=>	"signed long"
	"CUs"	=>	"const unsigned short"

   The value returned is really a type_kind_t.  */

static int
demangle_fund_type (struct work_stuff *work,
                    const char **mangled, string *result)
{
  int done = 0;
  int success = 1;
  char buf[INTBUF_SIZE + 5 /* 'int%u_t' */];
  unsigned int dec = 0;
  type_kind_t tk = tk_integral;

  /* First pick off any type qualifiers.  There can be more than one.  */

  while (!done)
    {
      switch (**mangled)
	{
	case 'C':
	case 'V':
	case 'u':
	  if (PRINT_ANSI_QUALIFIERS)
	    {
              if (!STRING_EMPTY (result))
                string_prepend (result, " ");
	      string_prepend (result, demangle_qualifier (**mangled));
	    }
	  (*mangled)++;
	  break;
	case 'U':
	  (*mangled)++;
	  APPEND_BLANK (result);
	  string_append (result, "unsigned");
	  break;
	case 'S': /* signed char only */
	  (*mangled)++;
	  APPEND_BLANK (result);
	  string_append (result, "signed");
	  break;
	case 'J':
	  (*mangled)++;
	  APPEND_BLANK (result);
	  string_append (result, "__complex");
	  break;
	default:
	  done = 1;
	  break;
	}
    }

  /* Now pick off the fundamental type.  There can be only one.  */

  switch (**mangled)
    {
    case '\0':
    case '_':
      break;
    case 'v':
      (*mangled)++;
      APPEND_BLANK (result);
      string_append (result, "void");
      break;
    case 'x':
      (*mangled)++;
      APPEND_BLANK (result);
      string_append (result, "long long");
      break;
    case 'l':
      (*mangled)++;
      APPEND_BLANK (result);
      string_append (result, "long");
      break;
    case 'i':
      (*mangled)++;
      APPEND_BLANK (result);
      string_append (result, "int");
      break;
    case 's':
      (*mangled)++;
      APPEND_BLANK (result);
      string_append (result, "short");
      break;
    case 'b':
      (*mangled)++;
      APPEND_BLANK (result);
      string_append (result, "bool");
      tk = tk_bool;
      break;
    case 'c':
      (*mangled)++;
      APPEND_BLANK (result);
      string_append (result, "char");
      tk = tk_char;
      break;
    case 'w':
      (*mangled)++;
      APPEND_BLANK (result);
      string_append (result, "wchar_t");
      tk = tk_char;
      break;
    case 'r':
      (*mangled)++;
      APPEND_BLANK (result);
      string_append (result, "long double");
      tk = tk_real;
      break;
    case 'd':
      (*mangled)++;
      APPEND_BLANK (result);
      string_append (result, "double");
      tk = tk_real;
      break;
    case 'f':
      (*mangled)++;
      APPEND_BLANK (result);
      string_append (result, "float");
      tk = tk_real;
      break;
    case 'G':
      (*mangled)++;
      if (!ISDIGIT ((unsigned char)**mangled))
	{
	  success = 0;
	  break;
	}
    case 'I':
      (*mangled)++;
      if (**mangled == '_')
	{
	  int i;
	  (*mangled)++;
	  for (i = 0;
	       i < (long) sizeof (buf) - 1 && **mangled && **mangled != '_';
	       (*mangled)++, i++)
	    buf[i] = **mangled;
	  if (**mangled != '_')
	    {
	      success = 0;
	      break;
	    }
	  buf[i] = '\0';
	  (*mangled)++;
	}
      else
	{
	  strncpy (buf, *mangled, 2);
	  buf[2] = '\0';
	  *mangled += min (strlen (*mangled), 2);
	}
      sscanf (buf, "%x", &dec);
      sprintf (buf, "int%u_t", dec);
      APPEND_BLANK (result);
      string_append (result, buf);
      break;

      /* fall through */
      /* An explicit type, such as "6mytype" or "7integer" */
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      {
        int bindex = register_Btype (work);
        string btype;
        string_init (&btype);
        if (demangle_class_name (work, mangled, &btype)) {
          remember_Btype (work, btype.b, LEN_STRING (&btype), bindex);
          APPEND_BLANK (result);
          string_appends (result, &btype);
        }
        else
          success = 0;
        string_delete (&btype);
        break;
      }
    case 't':
      {
        string btype;
        string_init (&btype);
        success = demangle_template (work, mangled, &btype, 0, 1, 1);
        string_appends (result, &btype);
        string_delete (&btype);
        break;
      }
    default:
      success = 0;
      break;
    }

  return success ? ((int) tk) : 0;
}


/* Handle a template's value parameter for HP aCC (extension from ARM)
   **mangled points to 'S' or 'U' */

static int
do_hpacc_template_const_value (struct work_stuff *work ATTRIBUTE_UNUSED,
                               const char **mangled, string *result)
{
  int unsigned_const;

  if (**mangled != 'U' && **mangled != 'S')
    return 0;

  unsigned_const = (**mangled == 'U');

  (*mangled)++;

  switch (**mangled)
    {
      case 'N':
        string_append (result, "-");
        /* fall through */
      case 'P':
        (*mangled)++;
        break;
      case 'M':
        /* special case for -2^31 */
        string_append (result, "-2147483648");
        (*mangled)++;
        return 1;
      default:
        return 0;
    }

  /* We have to be looking at an integer now */
  if (!(ISDIGIT ((unsigned char)**mangled)))
    return 0;

  /* We only deal with integral values for template
     parameters -- so it's OK to look only for digits */
  while (ISDIGIT ((unsigned char)**mangled))
    {
      char_str[0] = **mangled;
      string_append (result, char_str);
      (*mangled)++;
    }

  if (unsigned_const)
    string_append (result, "U");

  /* FIXME? Some day we may have 64-bit (or larger :-) ) constants
     with L or LL suffixes. pai/1997-09-03 */

  return 1; /* success */
}

/* Handle a template's literal parameter for HP aCC (extension from ARM)
   **mangled is pointing to the 'A' */

static int
do_hpacc_template_literal (struct work_stuff *work, const char **mangled,
                           string *result)
{
  int literal_len = 0;
  char * recurse;
  char * recurse_dem;

  if (**mangled != 'A')
    return 0;

  (*mangled)++;

  literal_len = consume_count (mangled);

  if (literal_len <= 0)
    return 0;

  /* Literal parameters are names of arrays, functions, etc.  and the
     canonical representation uses the address operator */
  string_append (result, "&");

  /* Now recursively demangle the literal name */
  recurse = XNEWVEC (char, literal_len + 1);
  memcpy (recurse, *mangled, literal_len);
  recurse[literal_len] = '\000';

  recurse_dem = cplus_demangle (recurse, work->options);

  if (recurse_dem)
    {
      string_append (result, recurse_dem);
      free (recurse_dem);
    }
  else
    {
      string_appendn (result, *mangled, literal_len);
    }
  (*mangled) += literal_len;
  free (recurse);

  return 1;
}

static int
snarf_numeric_literal (const char **args, string *arg)
{
  if (**args == '-')
    {
      char_str[0] = '-';
      string_append (arg, char_str);
      (*args)++;
    }
  else if (**args == '+')
    (*args)++;

  if (!ISDIGIT ((unsigned char)**args))
    return 0;

  while (ISDIGIT ((unsigned char)**args))
    {
      char_str[0] = **args;
      string_append (arg, char_str);
      (*args)++;
    }

  return 1;
}

/* Demangle the next argument, given by MANGLED into RESULT, which
   *should be an uninitialized* string.  It will be initialized here,
   and free'd should anything go wrong.  */

static int
do_arg (struct work_stuff *work, const char **mangled, string *result)
{
  /* Remember where we started so that we can record the type, for
     non-squangling type remembering.  */
  const char *start = *mangled;

  string_init (result);

  if (work->nrepeats > 0)
    {
      --work->nrepeats;

      if (work->previous_argument == 0)
	return 0;

      /* We want to reissue the previous type in this argument list.  */
      string_appends (result, work->previous_argument);
      return 1;
    }

  if (**mangled == 'n')
    {
      /* A squangling-style repeat.  */
      (*mangled)++;
      work->nrepeats = consume_count(mangled);

      if (work->nrepeats <= 0)
	/* This was not a repeat count after all.  */
	return 0;

      if (work->nrepeats > 9)
	{
	  if (**mangled != '_')
	    /* The repeat count should be followed by an '_' in this
	       case.  */
	    return 0;
	  else
	    (*mangled)++;
	}

      /* Now, the repeat is all set up.  */
      return do_arg (work, mangled, result);
    }

  /* Save the result in WORK->previous_argument so that we can find it
     if it's repeated.  Note that saving START is not good enough: we
     do not want to add additional types to the back-referenceable
     type vector when processing a repeated type.  */
  if (work->previous_argument)
    string_delete (work->previous_argument);
  else
    work->previous_argument = XNEW (string);

  if (!do_type (work, mangled, work->previous_argument))
    return 0;

  string_appends (result, work->previous_argument);

  remember_type (work, start, *mangled - start);
  return 1;
}

static void
remember_type (struct work_stuff *work, const char *start, int len)
{
  char *tem;

  if (work->forgetting_types)
    return;

  if (work -> ntypes >= work -> typevec_size)
    {
      if (work -> typevec_size == 0)
	{
	  work -> typevec_size = 3;
	  work -> typevec = XNEWVEC (char *, work->typevec_size);
	}
      else
	{
	  work -> typevec_size *= 2;
	  work -> typevec
	    = XRESIZEVEC (char *, work->typevec, work->typevec_size);
	}
    }
  tem = XNEWVEC (char, len + 1);
  memcpy (tem, start, len);
  tem[len] = '\0';
  work -> typevec[work -> ntypes++] = tem;
}


/* Remember a K type class qualifier. */
static void
remember_Ktype (struct work_stuff *work, const char *start, int len)
{
  char *tem;

  if (work -> numk >= work -> ksize)
    {
      if (work -> ksize == 0)
	{
	  work -> ksize = 5;
	  work -> ktypevec = XNEWVEC (char *, work->ksize);
	}
      else
	{
	  work -> ksize *= 2;
	  work -> ktypevec
	    = XRESIZEVEC (char *, work->ktypevec, work->ksize);
	}
    }
  tem = XNEWVEC (char, len + 1);
  memcpy (tem, start, len);
  tem[len] = '\0';
  work -> ktypevec[work -> numk++] = tem;
}

/* Register a B code, and get an index for it. B codes are registered
   as they are seen, rather than as they are completed, so map<temp<char> >
   registers map<temp<char> > as B0, and temp<char> as B1 */

static int
register_Btype (struct work_stuff *work)
{
  int ret;

  if (work -> numb >= work -> bsize)
    {
      if (work -> bsize == 0)
	{
	  work -> bsize = 5;
	  work -> btypevec = XNEWVEC (char *, work->bsize);
	}
      else
	{
	  work -> bsize *= 2;
	  work -> btypevec
	    = XRESIZEVEC (char *, work->btypevec, work->bsize);
	}
    }
  ret = work -> numb++;
  work -> btypevec[ret] = NULL;
  return(ret);
}

/* Store a value into a previously registered B code type. */

static void
remember_Btype (struct work_stuff *work, const char *start,
                int len, int index)
{
  char *tem;

  tem = XNEWVEC (char, len + 1);
  memcpy (tem, start, len);
  tem[len] = '\0';
  work -> btypevec[index] = tem;
}

/* Lose all the info related to B and K type codes. */
static void
forget_B_and_K_types (struct work_stuff *work)
{
  int i;

  while (work -> numk > 0)
    {
      i = --(work -> numk);
      if (work -> ktypevec[i] != NULL)
	{
	  free (work -> ktypevec[i]);
	  work -> ktypevec[i] = NULL;
	}
    }

  while (work -> numb > 0)
    {
      i = --(work -> numb);
      if (work -> btypevec[i] != NULL)
	{
	  free (work -> btypevec[i]);
	  work -> btypevec[i] = NULL;
	}
    }
}
/* Forget the remembered types, but not the type vector itself.  */

static void
forget_types (struct work_stuff *work)
{
  int i;

  while (work -> ntypes > 0)
    {
      i = --(work -> ntypes);
      if (work -> typevec[i] != NULL)
	{
	  free (work -> typevec[i]);
	  work -> typevec[i] = NULL;
	}
    }
}

/* Process the argument list part of the signature, after any class spec
   has been consumed, as well as the first 'F' character (if any).  For
   example:

   "__als__3fooRT0"		=>	process "RT0"
   "complexfunc5__FPFPc_PFl_i"	=>	process "PFPc_PFl_i"

   DECLP must be already initialised, usually non-empty.  It won't be freed
   on failure.

   Note that g++ differs significantly from ARM and lucid style mangling
   with regards to references to previously seen types.  For example, given
   the source fragment:

     class foo {
       public:
       foo::foo (int, foo &ia, int, foo &ib, int, foo &ic);
     };

     foo::foo (int, foo &ia, int, foo &ib, int, foo &ic) { ia = ib = ic; }
     void foo (int, foo &ia, int, foo &ib, int, foo &ic) { ia = ib = ic; }

   g++ produces the names:

     __3fooiRT0iT2iT2
     foo__FiR3fooiT1iT1

   while lcc (and presumably other ARM style compilers as well) produces:

     foo__FiR3fooT1T2T1T2
     __ct__3fooFiR3fooT1T2T1T2

   Note that g++ bases its type numbers starting at zero and counts all
   previously seen types, while lucid/ARM bases its type numbers starting
   at one and only considers types after it has seen the 'F' character
   indicating the start of the function args.  For lucid/ARM style, we
   account for this difference by discarding any previously seen types when
   we see the 'F' character, and subtracting one from the type number
   reference.

 */

static int
demangle_args (struct work_stuff *work, const char **mangled,
               string *declp)
{
  string arg;
  int need_comma = 0;
  int r;
  int t;
  const char *tem;
  char temptype;

  if (PRINT_ARG_TYPES)
    {
      string_append (declp, "(");
      if (**mangled == '\0')
	{
	  string_append (declp, "void");
	}
    }

  while ((**mangled != '_' && **mangled != '\0' && **mangled != 'e')
	 || work->nrepeats > 0)
    {
      if ((**mangled == 'N') || (**mangled == 'T'))
	{
	  temptype = *(*mangled)++;

	  if (temptype == 'N')
	    {
	      if (!get_count (mangled, &r))
		{
		  return (0);
		}
	    }
	  else
	    {
	      r = 1;
	    }
          if ((HP_DEMANGLING || ARM_DEMANGLING || EDG_DEMANGLING) && work -> ntypes >= 10)
            {
              /* If we have 10 or more types we might have more than a 1 digit
                 index so we'll have to consume the whole count here. This
                 will lose if the next thing is a type name preceded by a
                 count but it's impossible to demangle that case properly
                 anyway. Eg if we already have 12 types is T12Pc "(..., type1,
                 Pc, ...)"  or "(..., type12, char *, ...)" */
              if ((t = consume_count(mangled)) <= 0)
                {
                  return (0);
                }
            }
          else
	    {
	      if (!get_count (mangled, &t))
	    	{
	          return (0);
	    	}
	    }
	  if (LUCID_DEMANGLING || ARM_DEMANGLING || HP_DEMANGLING || EDG_DEMANGLING)
	    {
	      t--;
	    }
	  /* Validate the type index.  Protect against illegal indices from
	     malformed type strings.  */
	  if ((t < 0) || (t >= work -> ntypes))
	    {
	      return (0);
	    }
	  while (work->nrepeats > 0 || --r >= 0)
	    {
	      tem = work -> typevec[t];
	      if (need_comma && PRINT_ARG_TYPES)
		{
		  string_append (declp, ", ");
		}
	      if (!do_arg (work, &tem, &arg))
		{
		  return (0);
		}
	      if (PRINT_ARG_TYPES)
		{
		  string_appends (declp, &arg);
		}
	      string_delete (&arg);
	      need_comma = 1;
	    }
	}
      else
	{
	  if (need_comma && PRINT_ARG_TYPES)
	    string_append (declp, ", ");
	  if (!do_arg (work, mangled, &arg))
	    return (0);
	  if (PRINT_ARG_TYPES)
	    string_appends (declp, &arg);
	  string_delete (&arg);
	  need_comma = 1;
	}
    }

  if (**mangled == 'e')
    {
      (*mangled)++;
      if (PRINT_ARG_TYPES)
	{
	  if (need_comma)
	    {
	      string_append (declp, ",");
	    }
	  string_append (declp, "...");
	}
    }

  if (PRINT_ARG_TYPES)
    {
      string_append (declp, ")");
    }
  return (1);
}

/* Like demangle_args, but for demangling the argument lists of function
   and method pointers or references, not top-level declarations.  */

static int
demangle_nested_args (struct work_stuff *work, const char **mangled,
                      string *declp)
{
  string* saved_previous_argument;
  int result;
  int saved_nrepeats;

  /* The G++ name-mangling algorithm does not remember types on nested
     argument lists, unless -fsquangling is used, and in that case the
     type vector updated by remember_type is not used.  So, we turn
     off remembering of types here.  */
  ++work->forgetting_types;

  /* For the repeat codes used with -fsquangling, we must keep track of
     the last argument.  */
  saved_previous_argument = work->previous_argument;
  saved_nrepeats = work->nrepeats;
  work->previous_argument = 0;
  work->nrepeats = 0;

  /* Actually demangle the arguments.  */
  result = demangle_args (work, mangled, declp);

  /* Restore the previous_argument field.  */
  if (work->previous_argument)
    {
      string_delete (work->previous_argument);
      free ((char *) work->previous_argument);
    }
  work->previous_argument = saved_previous_argument;
  --work->forgetting_types;
  work->nrepeats = saved_nrepeats;

  return result;
}

/* Returns 1 if a valid function name was found or 0 otherwise.  */

static int 
demangle_function_name (struct work_stuff *work, const char **mangled,
                        string *declp, const char *scan)
{
  size_t i;
  string type;
  const char *tem;

  string_appendn (declp, (*mangled), scan - (*mangled));
  string_need (declp, 1);
  *(declp -> p) = '\0';

  /* Consume the function name, including the "__" separating the name
     from the signature.  We are guaranteed that SCAN points to the
     separator.  */

  (*mangled) = scan + 2;
  /* We may be looking at an instantiation of a template function:
     foo__Xt1t2_Ft3t4, where t1, t2, ... are template arguments and a
     following _F marks the start of the function arguments.  Handle
     the template arguments first. */

  if (HP_DEMANGLING && (**mangled == 'X'))
    {
      demangle_arm_hp_template (work, mangled, 0, declp);
      /* This leaves MANGLED pointing to the 'F' marking func args */
    }

  if (LUCID_DEMANGLING || ARM_DEMANGLING || HP_DEMANGLING || EDG_DEMANGLING)
    {

      /* See if we have an ARM style constructor or destructor operator.
	 If so, then just record it, clear the decl, and return.
	 We can't build the actual constructor/destructor decl until later,
	 when we recover the class name from the signature.  */

      if (strcmp (declp -> b, "__ct") == 0)
	{
	  work -> constructor += 1;
	  string_clear (declp);
	  return 1;
	}
      else if (strcmp (declp -> b, "__dt") == 0)
	{
	  work -> destructor += 1;
	  string_clear (declp);
	  return 1;
	}
    }

  if (declp->p - declp->b >= 3
      && declp->b[0] == 'o'
      && declp->b[1] == 'p'
      && strchr (cplus_markers, declp->b[2]) != NULL)
    {
      /* see if it's an assignment expression */
      if (declp->p - declp->b >= 10 /* op$assign_ */
	  && memcmp (declp->b + 3, "assign_", 7) == 0)
	{
	  for (i = 0; i < ARRAY_SIZE (optable); i++)
	    {
	      int len = declp->p - declp->b - 10;
	      if ((int) strlen (optable[i].in) == len
		  && memcmp (optable[i].in, declp->b + 10, len) == 0)
		{
		  string_clear (declp);
		  string_append (declp, "operator");
		  string_append (declp, optable[i].out);
		  string_append (declp, "=");
		  break;
		}
	    }
	}
      else
	{
	  for (i = 0; i < ARRAY_SIZE (optable); i++)
	    {
	      int len = declp->p - declp->b - 3;
	      if ((int) strlen (optable[i].in) == len
		  && memcmp (optable[i].in, declp->b + 3, len) == 0)
		{
		  string_clear (declp);
		  string_append (declp, "operator");
		  string_append (declp, optable[i].out);
		  break;
		}
	    }
	}
    }
  else if (declp->p - declp->b >= 5 && memcmp (declp->b, "type", 4) == 0
	   && strchr (cplus_markers, declp->b[4]) != NULL)
    {
      /* type conversion operator */
      tem = declp->b + 5;
      if (do_type (work, &tem, &type))
	{
	  string_clear (declp);
	  string_append (declp, "operator ");
	  string_appends (declp, &type);
	  string_delete (&type);
	}
    }
  else if (declp->b[0] == '_' && declp->b[1] == '_'
	   && declp->b[2] == 'o' && declp->b[3] == 'p')
    {
      /* ANSI.  */
      /* type conversion operator.  */
      tem = declp->b + 4;
      if (do_type (work, &tem, &type))
	{
	  string_clear (declp);
	  string_append (declp, "operator ");
	  string_appends (declp, &type);
	  string_delete (&type);
	}
    }
  else if (declp->b[0] == '_' && declp->b[1] == '_'
	   && ISLOWER((unsigned char)declp->b[2])
	   && ISLOWER((unsigned char)declp->b[3]))
    {
      if (declp->b[4] == '\0')
	{
	  /* Operator.  */
	  for (i = 0; i < ARRAY_SIZE (optable); i++)
	    {
	      if (strlen (optable[i].in) == 2
		  && memcmp (optable[i].in, declp->b + 2, 2) == 0)
		{
		  string_clear (declp);
		  string_append (declp, "operator");
		  string_append (declp, optable[i].out);
		  break;
		}
	    }
	}
      else
	{
	  if (declp->b[2] == 'a' && declp->b[5] == '\0')
	    {
	      /* Assignment.  */
	      for (i = 0; i < ARRAY_SIZE (optable); i++)
		{
		  if (strlen (optable[i].in) == 3
		      && memcmp (optable[i].in, declp->b + 2, 3) == 0)
		    {
		      string_clear (declp);
		      string_append (declp, "operator");
		      string_append (declp, optable[i].out);
		      break;
		    }
		}
	    }
	}
    }

  /* If a function name was obtained but it's not valid, we were not
     successful.  */
  if (LEN_STRING (declp) == 1 && declp->b[0] == '.')
    return 0;
  else
    return 1;
}

/* a mini string-handling package */

static void
string_need (string *s, int n)
{
  int tem;

  if (s->b == NULL)
    {
      if (n < 32)
	{
	  n = 32;
	}
      s->p = s->b = XNEWVEC (char, n);
      s->e = s->b + n;
    }
  else if (s->e - s->p < n)
    {
      tem = s->p - s->b;
      n += tem;
      n *= 2;
      s->b = XRESIZEVEC (char, s->b, n);
      s->p = s->b + tem;
      s->e = s->b + n;
    }
}

static void
string_delete (string *s)
{
  if (s->b != NULL)
    {
      free (s->b);
      s->b = s->e = s->p = NULL;
    }
}

static void
string_init (string *s)
{
  s->b = s->p = s->e = NULL;
}

static void
string_clear (string *s)
{
  s->p = s->b;
}

#if 0

static int
string_empty (string *s)
{
  return (s->b == s->p);
}

#endif

static void
string_append (string *p, const char *s)
{
  int n;
  if (s == NULL || *s == '\0')
    return;
  n = strlen (s);
  string_need (p, n);
  memcpy (p->p, s, n);
  p->p += n;
}

static void
string_appends (string *p, string *s)
{
  int n;

  if (s->b != s->p)
    {
      n = s->p - s->b;
      string_need (p, n);
      memcpy (p->p, s->b, n);
      p->p += n;
    }
}

static void
string_appendn (string *p, const char *s, int n)
{
  if (n != 0)
    {
      string_need (p, n);
      memcpy (p->p, s, n);
      p->p += n;
    }
}

static void
string_prepend (string *p, const char *s)
{
  if (s != NULL && *s != '\0')
    {
      string_prependn (p, s, strlen (s));
    }
}

static void
string_prepends (string *p, string *s)
{
  if (s->b != s->p)
    {
      string_prependn (p, s->b, s->p - s->b);
    }
}

static void
string_prependn (string *p, const char *s, int n)
{
  char *q;

  if (n != 0)
    {
      string_need (p, n);
      for (q = p->p - 1; q >= p->b; q--)
	{
	  q[n] = q[0];
	}
      memcpy (p->b, s, n);
      p->p += n;
    }
}

static void
string_append_template_idx (string *s, int idx)
{
  char buf[INTBUF_SIZE + 1 /* 'T' */];
  sprintf(buf, "T%d", idx);
  string_append (s, buf);
}

static void
print_demangler_list (FILE *stream)
{
  const struct demangler_engine *demangler;

  fprintf (stream, "{%s", libiberty_demanglers->demangling_style_name);

  for (demangler = libiberty_demanglers + 1;
       demangler->demangling_style != unknown_demangling;
       ++demangler)
    fprintf (stream, ",%s", demangler->demangling_style_name);

  fprintf (stream, "}");
}

static const char * demangler_list = NULL;

/* The buffer should be big enough to hold the list. */
static char demangler_list_buffer [128];

const char *
get_demangler_list ()
{

  enum demangling_styles i;
  int start, len, left;

  if (!demangler_list)
    {
      demangler_list = demangler_list_buffer;
      demangler_list_buffer [0] = '{';

      start = 1;
      left = sizeof (demangler_list_buffer) - start;
  
      for (i = 0; i < unknown_demangling && left > 0; i++) 
      {	
	  strncpy (&demangler_list_buffer [start],
		   libiberty_demanglers [i].demangling_style_name, left);
	  len = (int)strlen (libiberty_demanglers [i].demangling_style_name);
	  start += len;
    	  if (left > 0)
	    {
	      demangler_list_buffer [start] = ',';
	      start++;
	      left -= len + 1;
	    }
	}

      if (left >= 0)
	{
	  demangler_list_buffer [--start] = '}';  
	}
    }

  return demangler_list;
}

/* To generate a standalone demangler program for testing purposes,
   just compile and link this file with -DMAIN and libiberty.a.  When
   run, it demangles each command line arg, or each stdin string, and
   prints the result on stdout.  */

#ifdef MAIN_CPLUS_DEM

#include "getopt.h"

static const char *program_name;
static const char *program_version = "1";//TODO ???? VERSION;

static void demangle_it PARAMS ((char *));
static void usage PARAMS ((FILE *, int)) ATTRIBUTE_NORETURN;
static void fatal PARAMS ((const char *)) ATTRIBUTE_NORETURN;

int strip_underscore = 0;

static int flags = DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE;

static void
demangle_it (char *mangled_name)
{
  char *result;
  unsigned int skip_first = 0;

  /* _ and $ are sometimes found at the start of function names
     in assembler sources in order to distinguish them from other
     names (eg register names).  So skip them here.  */
  if (mangled_name[0] == '.' || mangled_name[0] == '$')
    ++skip_first;
  if (strip_underscore && mangled_name[skip_first] == '_')
    ++skip_first;

  result = cplus_demangle (mangled_name + skip_first, flags);

  if (result == NULL)
    printf ("%s", mangled_name);
  else
    {
      if (mangled_name[0] == '.')
	putchar ('.');
      printf ("%s", result);
      free (result);
    }
}

static void
usage (stream, status)
     FILE *stream;
     int status;
{

	  fprintf (stream, "\
		Usage: %s [options] [mangled names]\n", program_name);
		  fprintf (stream, "\
		Options are:\n\
		  [-_|--strip-underscore]     Ignore first leading underscore\n");
		  fprintf (stream, "\
		  [-n|--no-strip-underscore]  Do not ignore a leading underscore\n");
		  fprintf (stream, "\
		  [-p|--no-params]            Do not display function arguments\n\
		  [-i|--no-verbose]           Do not show implementation details (if any)\n\
		  [-t|--types]                Also attempt to demangle type encodings\n\
		  [-s|--format ");
		  print_demangler_list (stream);
		  fprintf (stream, "]\n");
		
		  fprintf (stream, "\
		  [@<file>]                   Read extra options from <file>\n\
		  [-h|--help]                 Display this information\n\
		  [-v|--version]              Show the version information\n\
		Demangled names are displayed to stdout.\n\
		If a name cannot be demangled it is just echoed to stdout.\n\
		If no names are provided on the command line, stdin is read.\n");

	exit(status);
	
}	

static void
usage_old (stream, status)
     FILE *stream;
     int status;
{
  fprintf (stream, "\
Usage: %s [-_] [-n] [--strip-underscores] [--no-strip-underscores] \n",
	   program_name);

  fprintf (stream, "\
       [-s|--format ");
	print_demangler_list(stream);	
	fprintf (stream, " ]\n");

  fprintf (stream, "\
       [--help] [--version] [arg...]\n");
  exit (status);
}

#define MBUF_SIZE 32767
char mbuffer[MBUF_SIZE];

/* Defined in the automatically-generated underscore.c.  */
int prepends_underscore = 0;

static const struct option long_options[] = {
  {"strip-underscore", no_argument, NULL, '_'},
  {"format", required_argument, NULL, 's'},
  {"help", no_argument, NULL, 'h'},
  {"no-params", no_argument, NULL, 'p'},
  {"no-strip-underscores", no_argument, NULL, 'n'},
  {"no-verbose", no_argument, NULL, 'i'},
  {"types", no_argument, NULL, 't'},
  {"version", no_argument, NULL, 'v'},
  {NULL, no_argument, NULL, 0}
};

/* More 'friendly' abort that prints the line and file.
   config.h can #define abort fancy_abort if you like that sort of thing.  */

void
fancy_abort ()
{
  fatal ("Internal gcc abort.");
}


static const char *
standard_symbol_characters PARAMS ((void));

static const char *
hp_symbol_characters PARAMS ((void));

static const char *
gnu_v3_symbol_characters PARAMS ((void));

/* Return the string of non-alnum characters that may occur 
   as a valid symbol component, in the standard assembler symbol
   syntax.  */

static const char *
standard_symbol_characters ()
{
  return "_$.";
}


/* Return the string of non-alnum characters that may occur
   as a valid symbol name component in an HP object file.

   Note that, since HP's compiler generates object code straight from
   C++ source, without going through an assembler, its mangled
   identifiers can use all sorts of characters that no assembler would
   tolerate, so the alphabet this function creates is a little odd.
   Here are some sample mangled identifiers offered by HP:

	typeid*__XT24AddressIndExpClassMember_
	[Vftptr]key:__dt__32OrdinaryCompareIndExpClassMemberFv
	__ct__Q2_9Elf64_Dyn18{unnamed.union.#1}Fv

   This still seems really weird to me, since nowhere else in this
   file is there anything to recognize curly brackets, parens, etc.
   I've talked with Srikanth <srikanth@cup.hp.com>, and he assures me
   this is right, but I still strongly suspect that there's a
   misunderstanding here.

   If we decide it's better for c++filt to use HP's assembler syntax
   to scrape identifiers out of its input, here's the definition of
   the symbol name syntax from the HP assembler manual:

       Symbols are composed of uppercase and lowercase letters, decimal
       digits, dollar symbol, period (.), ampersand (&), pound sign(#) and
       underscore (_). A symbol can begin with a letter, digit underscore or
       dollar sign. If a symbol begins with a digit, it must contain a
       non-digit character.

   So have fun.  */
static const char *
hp_symbol_characters ()
{
  return "_$.<>#,*&[]:(){}";
}


/* Return the string of non-alnum characters that may occur 
   as a valid symbol component in the GNU C++ V3 ABI mangling
   scheme.  */

static const char *
gnu_v3_symbol_characters ()
{
  return "_$.";
}


extern int main PARAMS ((int, char **));

int main (int argc, char ** argv) {
	int c;
	const char *valid_symbols;
	const char *demangler = NULL;
	const char *options = NULL;

	program_name = argv[0];

	strip_underscore = prepends_underscore;

	expandargv (&argc, &argv);

	while ((c = getopt_long (argc, argv, "_hinps:tv", long_options, (int *) 0)) != EOF)
	{
		switch (c)
		{
		case '?':
		  usage (stderr, 1);
		  break;
		case 'h':
		  usage (stdout, 0);
		case 'n':
		  strip_underscore = 0;
		  break;
		case 'p':
		  flags &= ~ DMGL_PARAMS;
		  break;
		case 't':
		  flags |= DMGL_TYPES;
		  break;
		case 'i':
		  flags &= ~ DMGL_VERBOSE;
		  break;
		case 'v':
		  printf ("GNU %s (C++ demangler), version %s\n", program_name, program_version);
		  return 0;
		case '_':
		  strip_underscore = 1;
		  break;
		case 's':
			current_demangling_style
				= cplus_demangle_name_to_style (optarg);
			if (current_demangling_style == unknown_demangling)
			{
				fprintf (stderr, "%s: unknown demangling style `%s'\n",
					program_name, optarg);
				return (1);
			}
			break;
		}
	}

	if (optind < argc)
	{
		for ( ; optind < argc; optind++)
		{
			demangle_it (argv[optind]);
			putchar ('\n');
		}
	}
	else
	{
		switch (current_demangling_style)
		{
		case gnu_demangling:
		case lucid_demangling:
		case arm_demangling:
		case java_demangling:
		case edg_demangling:
		case gnat_demangling:
		case auto_demangling:
			valid_symbols = standard_symbol_characters ();
			break;
		case hp_demangling:
			valid_symbols = hp_symbol_characters ();
			break;
		case gnu_v3_demangling:
			valid_symbols = gnu_v3_symbol_characters ();
			break;
		default:
			/* Folks should explicitly indicate the appropriate alphabet for
			each demangling.  Providing a default would allow the
			question to go unconsidered.  */
			abort ();
		}

		for (;;)
		{
			int i = 0;
			c = getchar ();
			/* Try to read a label.  */
			while (c != EOF && (ISALNUM (c) || strchr (valid_symbols, c)))
			{
				if (i >= MBUF_SIZE-1)
					break;
				mbuffer[i++] = c;
				c = getchar ();
			}
			if (i > 0)
			{
				int skip_first = 0;

				if (mbuffer[0] == '.' || mbuffer[0] == '$')
					++skip_first;
				if (strip_underscore && mbuffer[skip_first] == '_')
					++skip_first;

				if (skip_first > i)
					skip_first = i;

				mbuffer[i] = 0;
				demangle_it (mbuffer + skip_first);

				fflush (stdout);
			}
			if (c == EOF)
				break;
			putchar (c);
			if (c == '\n')
			fflush (stdout);
		}
	}

	return (0);
}

static void
fatal (str)
     const char *str;
{
  fprintf (stderr, "%s: %s\n", program_name, str);
  exit (1);
}

PTR
xmalloc (size)
  size_t size;
{
  register PTR value = (PTR) malloc (size);
  if (value == 0)
    fatal ("virtual memory exhausted");
  return value;
}

PTR
xrealloc (ptr, size)
  PTR ptr;
  size_t size;
{
  register PTR value = (PTR) realloc (ptr, size);
  if (value == 0)
    fatal ("virtual memory exhausted");
  return value;
}
#endif	/* main */
