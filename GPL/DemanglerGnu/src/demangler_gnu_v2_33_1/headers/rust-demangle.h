/* ###
 * IP: LGPL 2.1
 * NOTE: See binutils/libiberty/COPYING.LIB
 */
/* Internal demangler interface for the Rust programming language.
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

/* This file provides some definitions shared by cplus-dem.c and
   rust-demangle.c.  It should not be included by any other files.  */

/* Returns non-zero iff MANGLED is a rust mangled symbol.  MANGLED must
   already have been demangled through cplus_demangle_v3.  If this function
   returns non-zero then MANGLED can be demangled (in-place) using
   RUST_DEMANGLE_SYM.  */
extern int
rust_is_mangled (const char *mangled);

/* Demangles SYM (in-place) if RUST_IS_MANGLED returned non-zero for SYM.
   If RUST_IS_MANGLED returned zero for SYM then RUST_DEMANGLE_SYM might
   replace characters that cannot be demangled with '?' and might truncate
   SYM.  After calling RUST_DEMANGLE_SYM SYM might be shorter, but never
   larger.  */
extern void
rust_demangle_sym (char *sym);
