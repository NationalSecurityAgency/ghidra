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

#include "metatype.hh"

namespace ghidra {

/// Convert a type \b meta-type into the string name of the meta-type
/// \param metatype is the encoded type meta-type
/// \param res will hold the resulting string
void metatype2string(type_metatype metatype,string &res)

{
  switch(metatype) {
  case TYPE_VOID:
    res = "void";
    break;
  case TYPE_PTR:
    res = "ptr";
    break;
  case TYPE_PTRREL:
    res = "ptrrel";
    break;
  case TYPE_ARRAY:
    res = "array";
    break;
  case TYPE_PARTIALENUM:
    res = "partenum";
    break;
  case TYPE_PARTIALSTRUCT:
    res = "partstruct";
    break;
  case TYPE_PARTIALUNION:
    res = "partunion";
    break;
  case TYPE_ENUM_INT:
    res = "enum_int";
    break;
  case TYPE_ENUM_UINT:
    res = "enum_uint";
    break;
  case TYPE_STRUCT:
    res = "struct";
    break;
  case TYPE_UNION:
    res = "union";
    break;
  case TYPE_SPACEBASE:
    res = "spacebase";
    break;
  case TYPE_UNKNOWN:
    res = "unknown";
    break;
  case TYPE_UINT:
    res = "uint";
    break;
  case TYPE_INT:
    res = "int";
    break;
  case TYPE_BOOL:
    res = "bool";
    break;
  case TYPE_CODE:
    res = "code";
    break;
  case TYPE_FLOAT:
    res = "float";
    break;
  default:
    throw LowlevelError("Unknown metatype");
  }
}

/// Given a string description of a type \b meta-type. Return the meta-type.
/// \param metastring is the description of the meta-type
/// \return the encoded type meta-type
type_metatype string2metatype(const string &metastring)

{
  switch(metastring[0]) {
  case 'p':
    if (metastring=="ptr")
      return TYPE_PTR;
    else if (metastring=="ptrrel")
      return TYPE_PTRREL;
    else if (metastring=="partunion")
      return TYPE_PARTIALUNION;
    else if (metastring=="partstruct")
      return TYPE_PARTIALSTRUCT;
    break;
  case 'a':
    if (metastring=="array")
      return TYPE_ARRAY;
    break;
  case 'e':
    if (metastring=="enum_int")
      return TYPE_ENUM_INT;
    else if (metastring == "enum_uint")
      return TYPE_ENUM_UINT;
    break;
  case 's':
    if (metastring=="struct")
      return TYPE_STRUCT;
    if (metastring=="spacebase")
      return TYPE_SPACEBASE;
    break;
  case 'u':
    if (metastring=="unknown")
      return TYPE_UNKNOWN;
    else if (metastring=="uint")
      return TYPE_UINT;
    else if (metastring=="union")
      return TYPE_UNION;
    break;
  case 'i':
    if (metastring == "int")
      return TYPE_INT;
    break;
  case 'f':
    if (metastring == "float")
      return TYPE_FLOAT;
    break;
  case 'b':
    if (metastring == "bool")
      return TYPE_BOOL;
    break;
  case 'c':
    if (metastring == "code")
      return TYPE_CODE;
    break;
  case 'v':
    if (metastring == "void")
      return TYPE_VOID;
    break;
  default:
    break;
  }
  throw LowlevelError("Unknown metatype: "+metastring);
}

} // End namespace ghidra
