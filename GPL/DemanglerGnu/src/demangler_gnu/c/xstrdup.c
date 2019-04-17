/* ###
 * IP: LGPL 2.1
 * REVIEWED: YES
 * NOTE: license is not in file, but in the directory from whence it came: binutils-2.24/libiberty/COPYING.LIB
 */
/* xstrdup.c -- Duplicate a string in memory, using xmalloc.
   This trivial function is in the public domain.
   Ian Lance Taylor, Cygnus Support, December 1995.  */

/*

@deftypefn Replacement char* xstrdup (const char *@var{s})

Duplicates a character string without fail, using @code{xmalloc} to
obtain memory.

@end deftypefn

*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#ifdef HAVE_STRING_H
#include <string.h>
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif
#include "ansidecl.h"
#include "libiberty.h"

char *
xstrdup (const char *s)
{
  register size_t len = strlen (s) + 1;
  register char *ret = XNEWVEC (char, len);
  return (char *) memcpy (ret, s, len);
}
