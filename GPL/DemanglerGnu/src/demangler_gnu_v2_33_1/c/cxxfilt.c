/* ###
 * IP: GPL 3
 */
/* Demangler for GNU C++ - main program
   Copyright (C) 1989-2019 Free Software Foundation, Inc.
   Written by James Clark (jjc@jclark.uucp)
   Rewritten by Fred Fish (fnf@cygnus.com) for ARM and Lucid demangling
   Modified by Satish Pai (pai@apollo.hp.com) for HP demangling

   This file is part of GNU Binutils.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GCC; see the file COPYING.  If not, write to the Free
   Software Foundation, 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  

	   					CHANGE NOTICE:
		This file was changed on July 22nd, 2020.
   
*/

#include <stdlib.h>
#include <string.h>

#include "libiberty.h"
#include "demangle.h"
#include "getopt.h"
#include "safe-ctype.h"

static int flags = DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE;
static int strip_underscore = 0; // TARGET_PREPENDS_UNDERSCORE; // Changed Jan 22, 2020
static const char *program_name;								// Changed Jan 22, 2020

static const struct option long_options[] =
{
  {"strip-underscore", no_argument, NULL, '_'},
  {"format", required_argument, NULL, 's'},
  {"help", no_argument, NULL, 'h'},
  {"no-params", no_argument, NULL, 'p'},
  {"no-strip-underscores", no_argument, NULL, 'n'},
  {"no-verbose", no_argument, NULL, 'i'},
  {"types", no_argument, NULL, 't'},
  {"version", no_argument, NULL, 'v'},
  {"recurse-limit", no_argument, NULL, 'R'},
  {"recursion-limit", no_argument, NULL, 'R'},
  {"no-recurse-limit", no_argument, NULL, 'r'},
  {"no-recursion-limit", no_argument, NULL, 'r'},
  {NULL, no_argument, NULL, 0}
};

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

ATTRIBUTE_NORETURN static void
usage (FILE *stream, int status)
{
  fprintf (stream, "\
Usage: %s [options] [mangled names]\n", program_name);
  fprintf (stream, "\
Options are:\n\
  [-_|--strip-underscore]     Ignore first leading underscore%s\n",
	   strip_underscore ? " (default)" : "");					// Changed Jan 22, 2020
  fprintf (stream, "\
  [-n|--no-strip-underscore]  Do not ignore a leading underscore%s\n",
	   strip_underscore ? "" : " (default)");					// Changed Jan 22, 2020
  fprintf (stream, "\
  [-p|--no-params]            Do not display function arguments\n\
  [-i|--no-verbose]           Do not show implementation details (if any)\n\
  [-R|--recurse-limit]        Enable a limit on recursion whilst demangling.  [Default]\n\
  ]-r|--no-recurse-limit]     Disable a limit on recursion whilst demangling\n\
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

	/* Changed Jan 22, 2020
  if (REPORT_BUGS_TO[0] && status == 0)
    fprintf (stream, _("Report bugs to %s.\n"), REPORT_BUGS_TO);
    */ 
   
  exit (status);
}

/* Return the string of non-alnum characters that may occur
   as a valid symbol component, in the standard assembler symbol
   syntax.  */

static const char *
standard_symbol_characters (void)
{
  return "_$.";
}

extern int main (int, char **);

int
main (int argc, char **argv)
{
  int c;
  const char *valid_symbols;
  enum demangling_styles style = auto_demangling;

  program_name = argv[0];
  // xmalloc_set_program_name (program_name);   // Changed Jan 22, 2020
  // bfd_set_error_program_name (program_name); // Changed Jan 22, 2020

  expandargv (&argc, &argv);

  while ((c = getopt_long (argc, argv, "_hinprRs:tv", long_options, (int *) 0)) != EOF)
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
	case 'r':
	  flags |= DMGL_NO_RECURSE_LIMIT;
	  break;
	case 'R':
	  flags &= ~ DMGL_NO_RECURSE_LIMIT;
	  break;
	case 't':
	  flags |= DMGL_TYPES;
	  break;
	case 'i':
	  flags &= ~ DMGL_VERBOSE;
	  break;
	case 'v':
		printf ("(GNU Binutils) c++filt 2.33.1\n"); // Changed Jan 22, 2020
	  return 0;
	case '_':
	  strip_underscore = 1;
	  break;
	case 's':
	  style = cplus_demangle_name_to_style (optarg);
	  if (style == unknown_demangling)
	    {
	      fprintf (stderr, "%s: unknown demangling style `%s'\n",
		       program_name, optarg);
	      return 1;
	    }
	  cplus_demangle_set_style (style);
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

      return 0;
    }

  switch (current_demangling_style)
    {
    case auto_demangling:
    case gnu_v3_demangling:
    case java_demangling:
    case gnat_demangling:
    case dlang_demangling:
    case rust_demangling:
       valid_symbols = standard_symbol_characters ();
      break;
    default: {
      /* Folks should explicitly indicate the appropriate alphabet for
	 each demangling.  Providing a default would allow the
	 question to go unconsidered.  */
	    fprintf (stderr, "Internal error: no symbol alphabet for current style\n");	// Changed Jan 22, 2020	
  		exit (1);                                       							// Changed Jan 22, 2020
  	  }
    }

  for (;;)
    {
      static char mbuffer[32767];
      unsigned i = 0;

      c = getchar ();
      /* Try to read a mangled name.  */
      while (c != EOF && (ISALNUM (c) || strchr (valid_symbols, c)))
	{
	  if (i >= sizeof (mbuffer) - 1)
	    break;
	  mbuffer[i++] = c;
	  c = getchar ();
	}

      if (i > 0)
	{
	  mbuffer[i] = 0;
	  demangle_it (mbuffer);
	}

      if (c == EOF)
	break;

      /* Echo the whitespace characters so that the output looks
	 like the input, only with the mangled names demangled.  */
      putchar (c);
      if (c == '\n')
	fflush (stdout);
    }

  fflush (stdout);
  return 0;
}
