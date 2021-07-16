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
#include "pcode_test.h"

PCODE_COMPLEX_LOGIC(u4)
PCODE_COMPLEX_LOGIC(i4)

PCODE_COMPARE_LOGIC(u4)
PCODE_COMPARE_LOGIC(i4)

PCODE_GREATERTHAN(u4)
PCODE_GREATERTHAN(i4)

PCODE_GREATERTHANEQUALS(u4)
PCODE_GREATERTHANEQUALS(i4)

PCODE_LESSTHAN(u4)
PCODE_LESSTHAN(i4)

PCODE_LESSTHANEQUALS(u4)
PCODE_LESSTHANEQUALS(i4)

PCODE_EQUALS(u4)
PCODE_EQUALS(i4)

PCODE_NOTEQUALS(u4)
PCODE_NOTEQUALS(i4)

PCODE_BITWISE_AND(u4)
PCODE_BITWISE_AND(i4)

PCODE_BITWISE_OR(u4)
PCODE_BITWISE_OR(i4)

PCODE_LOGICAL_AND(u4)
PCODE_LOGICAL_AND(i4)

PCODE_LOGICAL_OR(u4)
PCODE_LOGICAL_OR(i4)

PCODE_LOGICAL_NOT(u4)
PCODE_LOGICAL_NOT(i4)

PCODE_XOR(u4)
PCODE_XOR(i4)

PCODE_SHIFTLEFT(u4)
PCODE_SHIFTLEFT(i4)

PCODE_SHIFTRIGHT(u4)
PCODE_SHIFTRIGHT(i4)

PCODE_UNARY_PLUS(u4)
PCODE_UNARY_PLUS(i4)

PCODE_UNARY_MINUS(u4)
PCODE_UNARY_MINUS(i4)

PCODE_ADDITION(u4)
PCODE_ADDITION(i4)

PCODE_SUBTRACT(u4)
PCODE_SUBTRACT(i4)

#ifdef HAS_MULTIPLY

PCODE_MUL(u4)
PCODE_MUL(i4)

#endif /* #ifdef HAS_MULTIPLY */
#ifdef HAS_DIVIDE

PCODE_DIV(u4)
PCODE_DIV(i4)

PCODE_REM(u4)
PCODE_REM(i4)

#endif /* #ifdef HAS_DIVIDE */
