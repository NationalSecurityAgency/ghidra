/* ###
 * IP: GHIDRA
 * REVIEWED: YES
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//
//  ghidra.h
//  GHIDRA
//

#ifndef GHIDRA_ghidra_h
#define GHIDRA_ghidra_h

#define G_CPU_TYPE_X86      0x1 // x86 32-bit little endian
#define G_CPU_TYPE_PPC      0x2 // ppc 32-bit little endian
#define G_CPU_TYPE_ARM      0x4 // arm 32-bit little endian

#define G_MAGIC             "ghidra"

#define	G_OBJECT_FILE       0x1 // relocatable object file
#define	G_EXECUTABLE_FILE   0x2 // demand paged executable file
#define	G_LIBRARY_FILE      0x3 // fixed VM shared library file
#define	G_KERNEL_OBJECT     0x4 // core file

struct ghidra_header {
	char            magic[ 6 ];   // magic number identifier
	unsigned char   cputype;      // cpu specifier
	unsigned short  nsections;    // number of sections
	unsigned short  nsymbols;     // number of symbols
	unsigned int    flags;        // flags
};

#define G_SECTION_READ      0x1
#define G_SECTION_WRITE     0x2
#define G_SECTION_EXECUTE   0x4

struct ghidra_section { // for 32-bit architectures
	char          name[ 16 ];     // name of this section
	unsigned int  addr;           // memory address of this section
	unsigned int  size;           // size in bytes of this section
	unsigned int  offset;         // file offset of this section
	unsigned int  flags;          // flags (section type and attributes
};

#define	G_SYMBOL_TYPE_ENTRY_POINT 0x1
#define	G_SYMBOL_TYPE_DATA        0x2

struct ghidra_symbol { // for 32-bit architectures
	char           name[ 25 ];   //name of this symbol
	unsigned int   addr;         // memory address of this symbol
	unsigned short type;         // type of this symbol
};

#endif
