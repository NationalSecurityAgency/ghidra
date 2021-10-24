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

#ifdef HAS_LONGLONG

PCODE_COMPLEX_LOGIC(u8)
PCODE_COMPLEX_LOGIC(i8)

PCODE_COMPARE_LOGIC(u8)
PCODE_COMPARE_LOGIC(i8)

PCODE_GREATERTHAN(u8)
PCODE_GREATERTHAN(i8)

PCODE_GREATERTHANEQUALS(u8)
PCODE_GREATERTHANEQUALS(i8)

PCODE_LESSTHAN(u8)
PCODE_LESSTHAN(i8)

PCODE_LESSTHANEQUALS(u8)
PCODE_LESSTHANEQUALS(i8)

PCODE_EQUALS(u8)
PCODE_EQUALS(i8)

PCODE_NOTEQUALS(u8)
PCODE_NOTEQUALS(i8)

PCODE_BITWISE_AND(u8)
PCODE_BITWISE_AND(i8)

PCODE_BITWISE_OR(u8)
PCODE_BITWISE_OR(i8)

PCODE_LOGICAL_AND(u8)
PCODE_LOGICAL_AND(i8)

PCODE_LOGICAL_OR(u8)
PCODE_LOGICAL_OR(i8)

PCODE_LOGICAL_NOT(u8)
PCODE_LOGICAL_NOT(i8)

PCODE_XOR(u8)
PCODE_XOR(i8)

PCODE_SHIFTLEFT(u8)
PCODE_SHIFTLEFT(i8)

PCODE_SHIFTRIGHT(u8)
PCODE_SHIFTRIGHT(i8)

PCODE_UNARY_PLUS(u8)
PCODE_UNARY_PLUS(i8)

PCODE_UNARY_MINUS(u8)
PCODE_UNARY_MINUS(i8)

PCODE_ADDITION(u8)
PCODE_ADDITION(i8)

PCODE_SUBTRACT(u8)
PCODE_SUBTRACT(i8)

#ifdef HAS_MULTIPLY

PCODE_MUL(u8)
PCODE_MUL(i8)

#endif /* #ifdef HAS_MULTIPLY */
#ifdef HAS_DIVIDE

PCODE_DIV(u8)
PCODE_DIV(i8)

PCODE_REM(u8)
PCODE_REM(i8)

#endif /* #ifdef HAS_DIVIDE */
#endif /* #ifdef HAS_LONGLONG */
