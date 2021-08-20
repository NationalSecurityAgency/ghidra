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

u4 u4_adc_carry(u4 a, u4 b, u1 carry)
{
    u4 res = 0;
    u4 x = 0xffffffff;
    u4 y = 1;
    if (carry == 1) {
	    __asm__(
            ".syntax unified\n"
            "adds %[x_res],%[x],%[y]\n" /* set the carry flag */
            : [x_res] "=r" (x)
            : [x] "r" (x), [y] "r" (y)
        );
    } else {
	    __asm__(
            ".syntax unified\n"
            "adds %[x_res],%[y],%[y]\n" /* clear the carry flag */
            : [x_res] "=r" (x)
            : [y] "r" (y)
        );
    }
    __asm__(
        ".syntax unified\n"
        "adcs %[input_a],%[input_a],%[input_b]\n"
        "bcc  adc_nocarry\n"
        "ldr  %[result], =0x1\n"
        "b adc_end\n"
        "adc_nocarry:\n"
        "ldr  %[result], =0x0\n"
        "adc_end:\n"
        : [result] "=r" (res)
        : [input_a] "r" (a), [input_b] "r" (b)
    );
	return res;
}

u4 u4_adc_overflow(u4 a, u4 b, u1 carry)
{
    u4 res = 0;
    u4 x = 0xffffffff;
    u4 y = 1;
    if (carry == 1) {
	    __asm__(
            ".syntax unified\n"
            "adds %[x_res],%[x],%[y]\n" /* set the carry flag */
            : [x_res] "=r" (x)
            : [x] "r" (x), [y] "r" (y)
        );
    } else {
	    __asm__(
            ".syntax unified\n"
            "adds %[x_res],%[y],%[y]\n" /* clear the carry flag */
            : [x_res] "=r" (x)
            : [y] "r" (y)
        );
    }
    __asm__(
        ".syntax unified\n"
        "adcs %[input_a],%[input_a],%[input_b], lsr #1\n"
        "bvc  adc_noover\n"
        "ldr  %[result], =0x1\n"
        "b adc_o_end\n"
        "adc_noover:\n"
        "ldr  %[result], =0x0\n"
        "adc_o_end:\n"
        : [result] "=r" (res)
        : [input_a] "r" (a), [input_b] "r" (b)
    );
	return res;
}

u4 u4_sbc_carry(i4 a, i4 b, u1 carry)
{
    u4 res = 0;
    u4 x = 0xffffffff;
    u4 y = 1;
    if (carry == 1) {
	    __asm__(
            ".syntax unified\n"
            "adds %[x_res],%[x],%[y]\n" /* set the carry flag */
            : [x_res] "=r" (x)
            : [x] "r" (x), [y] "r" (y)
        );
    } else {
	    __asm__(
            ".syntax unified\n"
            "adds %[x_res],%[y],%[y]\n" /* clear the carry flag */
            : [x_res] "=r" (x)
            : [y] "r" (y)
        );
    }
    __asm__(
        ".syntax unified\n"
        "sbcs %[input_a],%[input_a],%[input_b]\n"
        "bcc  sbc_nocarry\n"
        "ldr  %[result], =0x1\n"
        "b sbc_end\n"
        "sbc_nocarry:\n"
        "ldr  %[result], =0x0\n"
        "sbc_end:\n"
        : [result] "=r" (res)
        : [input_a] "r" (a), [input_b] "r" (b)
    );
	return res;
}

i4 i4_sbc(i4 a, i4 b, u1 carry)
{
    u4 res = 0;
    u4 x = 0xffffffff;
    u4 y = 1;
    if (carry == 1) {
	    __asm__(
            ".syntax unified\n"
            "adds %[x_res],%[x],%[y]\n" /* set the carry flag */
            : [x_res] "=r" (x)
            : [x] "r" (x), [y] "r" (y)
        );
    } else {
	    __asm__(
            ".syntax unified\n"
            "adds %[x_res],%[y],%[y]\n" /* clear the carry flag */
            : [x_res] "=r" (x)
            : [y] "r" (y)
        );
    }
    __asm__(
        "sbc %[result],%[input_a],%[input_b]\n"
        : [result] "=r" (res)
        : [input_a] "r" (a), [input_b] "r" (b)
    );
	return res;
}
