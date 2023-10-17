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

PCODE_COMPLEX_LOGIC(u2)
PCODE_COMPLEX_LOGIC(i2)

PCODE_COMPARE_LOGIC(u2)
PCODE_COMPARE_LOGIC(i2)

PCODE_GREATERTHAN(u2)
PCODE_GREATERTHAN(i2)

PCODE_GREATERTHANEQUALS(u2)
PCODE_GREATERTHANEQUALS(i2)

PCODE_LESSTHAN(u2)
PCODE_LESSTHAN(i2)

PCODE_LESSTHANEQUALS(u2)
PCODE_LESSTHANEQUALS(i2)

PCODE_EQUALS(u2)
PCODE_EQUALS(i2)

PCODE_NOTEQUALS(u2)
PCODE_NOTEQUALS(i2)

PCODE_BITWISE_AND(u2)
PCODE_BITWISE_AND(i2)

PCODE_BITWISE_OR(u2)
PCODE_BITWISE_OR(i2)

PCODE_LOGICAL_AND(u2)
PCODE_LOGICAL_AND(i2)

PCODE_LOGICAL_OR(u2)
PCODE_LOGICAL_OR(i2)

PCODE_LOGICAL_NOT(u2)
PCODE_LOGICAL_NOT(i2)

PCODE_XOR(u2)
PCODE_XOR(i2)

PCODE_SHIFTLEFT(u2)
PCODE_SHIFTLEFT(i2)

PCODE_SHIFTRIGHT(u2)
PCODE_SHIFTRIGHT(i2)

PCODE_UNARY_PLUS(u2)
PCODE_UNARY_PLUS(i2)

PCODE_UNARY_MINUS(u2)
PCODE_UNARY_MINUS(i2)

PCODE_ADDITION(u2)
PCODE_ADDITION(i2)

PCODE_SUBTRACT(u2)
PCODE_SUBTRACT(i2)

#ifdef HAS_MULTIPLY

PCODE_MUL(u2)
PCODE_MUL(i2)

#endif /* #ifdef HAS_MULTIPLY */
#ifdef HAS_DIVIDE

PCODE_DIV(u2)
PCODE_DIV(i2)

PCODE_REM(u2)
PCODE_REM(i2)

#endif /* #ifdef HAS_DIVIDE */
