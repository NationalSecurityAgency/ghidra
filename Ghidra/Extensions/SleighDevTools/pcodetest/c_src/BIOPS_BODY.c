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

PCODE_COMPLEX_LOGIC(u1)
PCODE_COMPLEX_LOGIC(i1)

PCODE_COMPARE_LOGIC(u1)
PCODE_COMPARE_LOGIC(i1)

PCODE_GREATERTHAN(u1)
PCODE_GREATERTHAN(i1)

PCODE_GREATERTHANEQUALS(u1)
PCODE_GREATERTHANEQUALS(i1)

PCODE_LESSTHAN(u1)
PCODE_LESSTHAN(i1)

PCODE_LESSTHANEQUALS(u1)
PCODE_LESSTHANEQUALS(i1)

PCODE_EQUALS(u1)
PCODE_EQUALS(i1)

PCODE_NOTEQUALS(u1)
PCODE_NOTEQUALS(i1)

PCODE_BITWISE_AND(u1)
PCODE_BITWISE_AND(i1)

PCODE_BITWISE_OR(u1)
PCODE_BITWISE_OR(i1)

PCODE_LOGICAL_AND(u1)
PCODE_LOGICAL_AND(i1)

PCODE_LOGICAL_OR(u1)
PCODE_LOGICAL_OR(i1)

PCODE_LOGICAL_NOT(u1)
PCODE_LOGICAL_NOT(i1)

PCODE_XOR(u1)
PCODE_XOR(i1)

PCODE_SHIFTLEFT(u1)
PCODE_SHIFTLEFT(i1)

PCODE_SHIFTRIGHT(u1)
PCODE_SHIFTRIGHT(i1)

PCODE_UNARY_PLUS(u1)
PCODE_UNARY_PLUS(i1)

PCODE_UNARY_MINUS(u1)
PCODE_UNARY_MINUS(i1)

PCODE_ADDITION(u1)
PCODE_ADDITION(i1)

PCODE_SUBTRACT(u1)
PCODE_SUBTRACT(i1)

#ifdef HAS_MULTIPLY

PCODE_MUL(u1)
PCODE_MUL(i1)

#endif /* #ifdef HAS_MULTIPLY */
#ifdef HAS_DIVIDE

PCODE_DIV(u1)
PCODE_DIV(i1)

PCODE_REM(u1)
PCODE_REM(i1)

#endif /* #ifdef HAS_DIVIDE */
