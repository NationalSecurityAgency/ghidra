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
#include "opcodes.hh"
#include "types.h"

/// \brief Names of operations associated with their opcode number
///
/// Some of the names have been replaced with special placeholder
/// ops for the sleigh compiler and interpreter these are as follows:
///  -  MULTIEQUAL = BUILD
///  -  INDIRECT   = DELAY_SLOT
///  -  PTRADD     = LABEL
///  -  PTRSUB     = CROSSBUILD
static const char *opcode_name[] = {
  "BLANK", "COPY", "LOAD", "STORE",
  "BRANCH", "CBRANCH", "BRANCHIND", "CALL",
  "CALLIND", "CALLOTHER", "RETURN", "INT_EQUAL",
  "INT_NOTEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_LESS",
  "INT_LESSEQUAL", "INT_ZEXT", "INT_SEXT", "INT_ADD",
  "INT_SUB", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
  "INT_2COMP", "INT_NEGATE", "INT_XOR", "INT_AND",
  "INT_OR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
  "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM",
  "INT_SREM", "BOOL_NEGATE", "BOOL_XOR", "BOOL_AND",
  "BOOL_OR", "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS",
  "FLOAT_LESSEQUAL", "UNUSED1", "FLOAT_NAN", "FLOAT_ADD",
  "FLOAT_DIV", "FLOAT_MULT", "FLOAT_SUB", "FLOAT_NEG",
  "FLOAT_ABS", "FLOAT_SQRT", "INT2FLOAT", "FLOAT2FLOAT",
  "TRUNC", "CEIL", "FLOOR", "ROUND",
  "BUILD", "DELAY_SLOT", "PIECE", "SUBPIECE", "CAST",
  "LABEL", "CROSSBUILD", "SEGMENTOP", "CPOOLREF", "NEW",
  "INSERT", "EXTRACT", "POPCOUNT"
};

static const int4 opcode_indices[] = {
  0, 39, 37, 40, 38,  4,  6, 60,  7,  8,  9, 64,  5, 57,  1, 68, 66,
  61, 71, 55, 52, 47, 48, 41, 43, 44, 49, 46, 51, 42, 53, 50, 58, 70,
  54, 24, 19, 27, 21, 33, 11, 29, 15, 16, 32, 25, 12, 28, 35, 30,
  23, 22, 34, 18, 13, 14, 36, 31, 20, 26, 17, 65,  2, 69, 62, 72, 10, 59,
  67,  3, 63, 56, 45
};

/// \param opc is an OpCode value
/// \return the name of the operation as a string
const char *get_opname(OpCode opc)

{
  return opcode_name[opc];
}

/// \param nm is the name of an operation
/// \return the corresponding OpCode value
OpCode get_opcode(const string &nm)

{
  int4 min = 1;			// Don't include BLANK
  int4 max = CPUI_MAX-1;
  int4 cur,ind;

  while(min <= max) {		// Binary search
    cur = (min + max)/2;
    ind = opcode_indices[cur];	// Get opcode in cur's sort slot
    if (opcode_name[ind] < nm)
      min = cur + 1;		// Everything equal or below cur is less
    else if (opcode_name[ind] > nm)
      max = cur - 1;		// Everything equal or above cur is greater
    else
      return (OpCode)ind;	// Found the match
  }
  return (OpCode)0;	// Name isn't an op
}

/// Every comparison operation has a complementary form that produces
/// the opposite output on the same inputs. Set \b reorder to true if
/// the complimentary operation involves reordering the input parameters.
/// \param opc is the OpCode to complement
/// \param reorder is set to \b true if the inputs need to be reordered
/// \return the complementary OpCode or CPUI_MAX if not given a comparison operation
OpCode get_booleanflip(OpCode opc,bool &reorder)

{
  switch(opc) {
  case CPUI_INT_EQUAL:
    reorder = false;
    return CPUI_INT_NOTEQUAL;
  case CPUI_INT_NOTEQUAL:
    reorder = false;
    return CPUI_INT_EQUAL;
  case CPUI_INT_SLESS:
    reorder = true;
    return CPUI_INT_SLESSEQUAL;
  case CPUI_INT_SLESSEQUAL:
    reorder = true;
    return CPUI_INT_SLESS;
  case CPUI_INT_LESS:
    reorder = true;
    return CPUI_INT_LESSEQUAL;
  case CPUI_INT_LESSEQUAL:
    reorder = true;
    return CPUI_INT_LESS;
  case CPUI_BOOL_NEGATE:
    reorder = false;
    return CPUI_COPY;
  case CPUI_FLOAT_EQUAL:
    reorder = false;
    return CPUI_FLOAT_NOTEQUAL;
  case CPUI_FLOAT_NOTEQUAL:
    reorder = false;
    return CPUI_FLOAT_EQUAL;
  case CPUI_FLOAT_LESS:
    reorder = true;
    return CPUI_FLOAT_LESSEQUAL;
  case CPUI_FLOAT_LESSEQUAL:
    reorder = true;
    return CPUI_FLOAT_LESS;
  default:
    break;
  }
  return CPUI_MAX;
}
