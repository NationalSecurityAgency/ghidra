/* ###
 * IP: GHIDRA
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
/// \file metatype.hh
/// \brief Enumeration describing classes of data-types

#ifndef __METATYPE_HH__
#define __METATYPE_HH__

#include "error.hh"

namespace ghidra {

/// The core meta-types supported by the decompiler. These are sizeless templates
/// for the elements making up the type algebra.  Index is important for Datatype::base2sub array.
enum type_metatype {
  TYPE_VOID = 17,		///< Standard "void" type, absence of type
  TYPE_SPACEBASE = 16,		///< Placeholder for symbol/type look-up calculations
  TYPE_UNKNOWN = 15,		///< An unknown low-level type. Treated as an unsigned integer.
  TYPE_INT = 14,		///< Signed integer. Signed is considered less specific than unsigned in C
  TYPE_UINT = 13,		///< Unsigned integer
  TYPE_BOOL = 12,		///< Boolean
  TYPE_CODE = 11,		///< Data is actual executable code
  TYPE_FLOAT = 10,		///< Floating-point

  TYPE_PTR = 9,			///< Pointer data-type
  TYPE_PTRREL = 8,		///< Pointer relative to another data-type (specialization of TYPE_PTR)
  TYPE_ARRAY = 7,		///< Array data-type, made up of a sequence of "element" datatype
  TYPE_ENUM_UINT = 6,		///< Unsigned enumeration data-type (specialization of TYPE_UINT)
  TYPE_ENUM_INT = 5,		///< Signed enumeration data-type (specialization of TYPE_INT)
  TYPE_STRUCT = 4,		///< Structure data-type, made up of component datatypes
  TYPE_UNION = 3,		///< An overlapping union of multiple datatypes
  TYPE_PARTIALENUM = 2,		///< Part of an enumerated value (specialization of TYPE_UINT)
  TYPE_PARTIALSTRUCT = 1,	///< Part of a structure, stored separately from the whole
  TYPE_PARTIALUNION = 0		///< Part of a union
};

/// Convert type \b meta-type to name
extern void metatype2string(type_metatype metatype,string &res);

/// Convert string to type \b meta-type
extern type_metatype string2metatype(const string &metastring);

} // End namespace ghidra
#endif
