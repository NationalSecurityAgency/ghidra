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
/// \file opcodes.hh
/// \brief All the individual p-code operations

#ifndef __OPCODES_HH__
#define __OPCODES_HH__

#include <string>

namespace ghidra {

using std::string;

/// \brief The op-code defining a specific p-code operation (PcodeOp)
///
/// These break up into categories:
///   - Branching operations
///   - Load and Store
///   - Comparison operations
///   - Arithmetic operations
///   - Logical operations
///   - Extension and truncation operations
enum OpCode {
  CPUI_COPY = 1,		///< Copy one operand to another
  CPUI_LOAD = 2,		///< Load from a pointer into a specified address space
  CPUI_STORE = 3,		///< Store at a pointer into a specified address space

  CPUI_BRANCH = 4,		///< Always branch
  CPUI_CBRANCH = 5,		///< Conditional branch
  CPUI_BRANCHIND = 6,		///< Indirect branch (jumptable)

  CPUI_CALL = 7,		///< Call to an absolute address
  CPUI_CALLIND = 8,		///< Call through an indirect address
  CPUI_CALLOTHER = 9,		///< User-defined operation
  CPUI_RETURN = 10,		///< Return from subroutine

				// Integer/bit operations

  CPUI_INT_EQUAL = 11,		///< Integer comparison, equality (==)
  CPUI_INT_NOTEQUAL = 12,	///< Integer comparison, in-equality (!=)
  CPUI_INT_SLESS = 13,		///< Integer comparison, signed less-than (<)
  CPUI_INT_SLESSEQUAL = 14,	///< Integer comparison, signed less-than-or-equal (<=)
  CPUI_INT_LESS = 15,		///< Integer comparison, unsigned less-than (<)
				// This also indicates a borrow on unsigned substraction
  CPUI_INT_LESSEQUAL = 16,	///< Integer comparison, unsigned less-than-or-equal (<=)
  CPUI_INT_ZEXT = 17,		///< Zero extension
  CPUI_INT_SEXT = 18,		///< Sign extension
  CPUI_INT_ADD = 19,		///< Addition, signed or unsigned (+)
  CPUI_INT_SUB = 20,		///< Subtraction, signed or unsigned (-)
  CPUI_INT_CARRY = 21,		///< Test for unsigned carry
  CPUI_INT_SCARRY = 22,		///< Test for signed carry
  CPUI_INT_SBORROW = 23,	///< Test for signed borrow
  CPUI_INT_2COMP = 24,		///< Twos complement
  CPUI_INT_NEGATE = 25,		///< Logical/bitwise negation (~)
  CPUI_INT_XOR = 26,		///< Logical/bitwise exclusive-or (^)
  CPUI_INT_AND = 27,		///< Logical/bitwise and (&)
  CPUI_INT_OR = 28,		///< Logical/bitwise or (|)
  CPUI_INT_LEFT = 29,		///< Left shift (<<)
  CPUI_INT_RIGHT = 30,		///< Right shift, logical (>>)
  CPUI_INT_SRIGHT = 31,		///< Right shift, arithmetic (>>)
  CPUI_INT_MULT = 32,		///< Integer multiplication, signed and unsigned (*)
  CPUI_INT_DIV = 33,		///< Integer division, unsigned (/)
  CPUI_INT_SDIV = 34,		///< Integer division, signed (/)
  CPUI_INT_REM = 35,		///< Remainder/modulo, unsigned (%)
  CPUI_INT_SREM = 36,		///< Remainder/modulo, signed (%)

  CPUI_BOOL_NEGATE = 37,	///< Boolean negate (!)
  CPUI_BOOL_XOR = 38,		///< Boolean exclusive-or (^^)
  CPUI_BOOL_AND = 39,		///< Boolean and (&&)
  CPUI_BOOL_OR = 40,		///< Boolean or (||)

				// Floating point operations

  CPUI_FLOAT_EQUAL = 41,        ///< Floating-point comparison, equality (==)
  CPUI_FLOAT_NOTEQUAL = 42,	///< Floating-point comparison, in-equality (!=)
  CPUI_FLOAT_LESS = 43,		///< Floating-point comparison, less-than (<)
  CPUI_FLOAT_LESSEQUAL = 44,	///< Floating-point comparison, less-than-or-equal (<=)
  // Slot 45 is currently unused
  CPUI_FLOAT_NAN = 46,	        ///< Not-a-number test (NaN)
 
  CPUI_FLOAT_ADD = 47,          ///< Floating-point addition (+)
  CPUI_FLOAT_DIV = 48,          ///< Floating-point division (/)
  CPUI_FLOAT_MULT = 49,         ///< Floating-point multiplication (*)
  CPUI_FLOAT_SUB = 50,          ///< Floating-point subtraction (-)
  CPUI_FLOAT_NEG = 51,          ///< Floating-point negation (-)
  CPUI_FLOAT_ABS = 52,          ///< Floating-point absolute value (abs)
  CPUI_FLOAT_SQRT = 53,         ///< Floating-point square root (sqrt)

  CPUI_FLOAT_INT2FLOAT = 54,    ///< Convert an integer to a floating-point
  CPUI_FLOAT_FLOAT2FLOAT = 55,  ///< Convert between different floating-point sizes
  CPUI_FLOAT_TRUNC = 56,        ///< Round towards zero
  CPUI_FLOAT_CEIL = 57,         ///< Round towards +infinity
  CPUI_FLOAT_FLOOR = 58,        ///< Round towards -infinity
  CPUI_FLOAT_ROUND = 59,	///< Round towards nearest

				// Internal opcodes for simplification. Not
				// typically generated in a direct translation.

				// Data-flow operations
  CPUI_MULTIEQUAL = 60,		///< Phi-node operator
  CPUI_INDIRECT = 61,		///< Copy with an indirect effect
  CPUI_PIECE = 62,		///< Concatenate
  CPUI_SUBPIECE = 63,		///< Truncate

  CPUI_CAST = 64,		///< Cast from one data-type to another
  CPUI_PTRADD = 65,		///< Index into an array ([])
  CPUI_PTRSUB = 66,		///< Drill down to a sub-field  (->)
  CPUI_SEGMENTOP = 67,		///< Look-up a \e segmented address
  CPUI_CPOOLREF = 68,		///< Recover a value from the \e constant \e pool
  CPUI_NEW = 69,		///< Allocate a new object (new)
  CPUI_INSERT = 70,		///< Insert a bit-range
  CPUI_EXTRACT = 71,		///< Extract a bit-range
  CPUI_POPCOUNT = 72,		///< Count the 1-bits
  CPUI_LZCOUNT = 73,		///< Count the leading 0-bits

  CPUI_MAX = 74			///< Value indicating the end of the op-code values
};

extern const char *get_opname(OpCode opc);		///< Convert an OpCode to the name as a string
extern OpCode get_opcode(const string &nm);		///< Convert a name string to the matching OpCode

extern OpCode get_booleanflip(OpCode opc,bool &reorder);	///< Get the complementary OpCode

} // End namespace ghidra
#endif
