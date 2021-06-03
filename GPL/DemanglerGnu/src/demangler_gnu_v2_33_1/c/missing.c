/* ###
 * IP: LGPL 2.1
 * NOTE: Code copied from older version of cplus-dem.c that Ghidra had modified
 */
/* 
    Copyright (C) 2003-2019 Free Software Foundation, Inc.

    This file exists to provide code missing from sibling files in this directory.

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
	This file was created on January 22nd, 2020:
		-This code was copied and modified from a previous version of libiberty	

*/

#include <sys/types.h>
#include <stdio.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
void * malloc ();
void * realloc ();
#endif


static void
fatal (str)
     const char *str;
{
  fprintf (stderr, "%s\n", str);
  exit (1);
}


void *
xmalloc (size)
  size_t size;
{
  register void * value = malloc (size);
  if (value == 0)
    fatal ("virtual memory exhausted");
  return value;
}

void *
xrealloc (ptr, size)
  
  size_t size;
{
  register void * value = realloc (ptr, size);
  if (value == 0)
    fatal ("virtual memory exhausted");
  return value;
}
