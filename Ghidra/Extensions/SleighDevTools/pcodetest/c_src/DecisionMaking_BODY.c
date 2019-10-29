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

i4 pcode_DM1_IfElse(i4 arg1)
{
	if (arg1 == 0x42) {
		return 1;
	} else {
		return 0;
	}
}

i4 pcode_DM2_IfElseIfElse(i4 arg1)
{
	if (arg1 == 0x42) {
		return 1;
	} else if (arg1 == 0x69) {
		return 2;
	} else {
		return 0;
	}
}

i4 pcode_DM3_SmallSwitch(i4 arg1)
{
	switch (arg1) {
	case 0x42:
		return 1;
		break;
	case 0x69:
		return 2;
		break;
	default:
		return 0;
		break;
	}
}

i4 pcode_DM4_MediumSwitch(i4 arg1)
{
	switch (arg1) {
	case 0x42:
		return 1;
		break;
	case 0x69:
		return 2;
		break;
	case 0x101:
	case 0x102:
	case 0x103:
	case 0x104:
	case 0x105:
	case 0x106:
	case 0x107:
	case 0x108:
		return 3;
	default:
		return 0;
		break;
	}
}

i4 pcode_DM5_EQ_TernaryOperator(i4 arg1)
{
	return arg1 == 0x69 ? 1 : 0;
}

i4 pcode_DM6_NE_TernaryOperator(i4 arg1)
{
	return arg1 != 0x69 ? 1 : 0;
}

i4 pcode_DM7_LT_TernaryOperator(i4 arg1)
{
	return arg1 < 0x69 ? 1 : 0;
}

i4 pcode_DM8_GT_TernaryOperator(i4 arg1)
{
	return arg1 > 0x69 ? 1 : 0;
}

i4 pcode_DM9_LE_TernaryOperator(i4 arg1)
{
	return arg1 <= 0x69 ? 1 : 0;
}

i4 pcode_DM10_GE_TernaryOperator(i4 arg1)
{
	return arg1 >= 0x69 ? 1 : 0;
}
