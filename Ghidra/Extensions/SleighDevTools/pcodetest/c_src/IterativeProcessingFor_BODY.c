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

i4 pcode_StandardPostIncForLoop()
{
	i4 ii;
	i4 accum = 0;

	for (ii = 0; ii < 5; ii++) {
		accum += 5;
	}
	return accum;
}

i4 pcode_StandardPreIncForLoop()
{
	i4 ii;
	i4 accum = 0;

	for (ii = 0; ii <= 5; ++ii) {
		accum += 5;
	}
	return accum;
}

i4 pcode_StandardPostDecForLoop()
{
	i4 ii;
	i4 accum = 0;

	for (ii = 5; ii > 0; ii--) {
		accum += 5;
	}
	return accum;
}

i4 pcode_StandardPreDecForLoop()
{
	i4 ii;
	i4 accum = 0;

	for (ii = 5; ii >= 0; --ii) {
		accum += 5;
	}
	return accum;
}

i4 pcode_VarIncrementPostIncForLoop(i4 kk)
{
	i4 ii;
	i4 accum = 0;

	for (ii = 0; ii < 5; ii++) {
		accum += kk;
	}
	return accum;
}

i4 pcode_VarIncrementPreIncForLoop(i4 kk)
{
	i4 ii;
	i4 accum = 0;

	for (ii = 0; ii <= 5; ++ii) {
		accum += kk;
	}
	return accum;
}

i4 pcode_VarIncrementPreDecForLoop(i4 kk)
{
	i4 ii;
	i4 accum = 0;

	for (ii = 5; ii >= 0; --ii) {
		accum += kk;
	}
	return accum;
}

i4 pcode_VarIncrementPostDecForLoop(i4 kk)
{
	i4 ii;
	i4 accum = 0;

	for (ii = 5; ii > 0; ii--) {
		accum += kk;
	}
	return accum;
}

i4 pcode_VarIterationPostIncForLoop(i4 nn)
{
	i4 ii;
	i4 accum = 0;

	for (ii = 0; ii < nn; ii++) {
		accum += 5;
	}
	return accum;
}

i4 pcode_VarIterationPreIncForLoop(i4 nn)
{
	i4 ii;
	i4 accum = 0;

	for (ii = 0; ii <= nn; ++ii) {
		accum += 5;
	}
	return accum;
}

i4 pcode_VarIterationPostDecForLoop(i4 nn)
{
	i4 ii;
	i4 accum = 0;

	for (ii = nn; ii > 0; ii--) {
		accum += 5;
	}
	return accum;
}

i4 pcode_VarIterationPreDecForLoop(i4 nn)
{
	i4 ii;
	i4 accum = 0;

	for (ii = nn; ii >= 0; --ii) {
		accum += 5;
	}
	return accum;
}

i4 pcode_VariablePostIncForLoop(i4 kk, i4 nn)
{
	i4 ii;
	i4 accum = 0;

	for (ii = 0; ii < nn; ii++) {
		accum += kk;
	}
	return accum;
}

i4 pcode_VariablePreIncForLoop(i4 kk, i4 nn)
{
	i4 ii;
	i4 accum = 0;

	for (ii = 0; ii <= nn; ++ii) {
		accum += kk;
	}
	return accum;
}

i4 pcode_VariablePostDecForLoop(i4 kk, i4 nn)
{
	i4 ii;
	i4 accum = 0;

	for (ii = nn; ii > 0; ii--) {
		accum += kk;
	}
	return accum;
}

i4 pcode_VariablePreDecForLoop(i4 kk, i4 nn)
{
	i4 ii;
	i4 accum = 0;

	for (ii = nn; ii >= 0; --ii) {
		accum += kk;
	}
	return accum;
}

i4 pcode_SwitchedForLoop(i4 type, i4 kk, i4 jj, i4 nn)
{
	i4 ii;
	i4 accum = 0;

	for (ii = 0; ii < nn; ++ii) {
		if (type == 10) {
			accum += kk;
		} else {
			accum += jj;
		}
	}
	return accum;
}

i4 pcode_UnSwitchedForLoop(i4 type, i4 kk, i4 jj, i4 nn)
{
	i4 ii;
	i4 accum = 0;

	if (type == 10) {
		for (ii = 0; ii < nn; ++ii) {
			accum += kk;
		}
	} else {
		for (ii = 0; ii < nn; ++ii) {
			accum += jj;
		}
	}
	return accum;
}

i4 pcode_JammedForLoop(i4 kk, i4 jj, i4 nn)
{
	i4 ii;
	i4 accum1 = 0;
	i4 accum2 = 0;

	for (ii = 0; ii < nn; ++ii) {
		accum1 += kk;
		accum2 += jj;
	}
	return (accum1 << 16) | accum2;
}

i4 pcode_UnJammedForLoop(i4 kk, i4 jj, i4 nn)
{
	i4 ii;
	i4 accum1 = 0;
	i4 accum2 = 0;

	for (ii = 0; ii < nn; ++ii) {
		accum1 += kk;
	}
	for (ii = 0; ii < nn; ++ii) {
		accum2 += jj;
	}
	return (accum1 << 16) | accum2;
}

i4 pcode_RolledForLoop(i4 array[], i4 nn)
{
	i4 ii;
	i4 accum = 0;

	for (ii = 0; ii < nn;) {
		accum += array[ii++];
	}
	return accum;
}

i4 pcode_Unrolled2ForLoop(i4 array[], i4 nn)
{
	i4 ii;
	i4 accum = 0;
	i4 limit = nn & (~1);

	for (ii = 0; ii < limit;) {
		accum += array[ii] + array[ii + 1];
		ii += 2;
	}
	if (limit != nn) {
		accum += array[ii];
	}
	return accum;
}

i4 pcode_Unrolled4ForLoop(i4 array[], i4 nn)
{
	i4 ii;
	i4 accum = 0;
	i4 limit = nn & (~3);

	for (ii = 0; ii < limit;) {
		accum += array[ii] + array[ii + 1] + array[ii + 2] + array[ii + 3];
		ii += 4;
	}
	switch (nn - limit) {
	case 3:
		accum += array[ii++];
	case 2:
		accum += array[ii++];
	case 1:
		accum += array[ii];
	case 0:
		break;
	}
	return accum;
}

i4 pcode_testNestedLoop1(i4 a)
{
	i4 result = 0;
	i4 i = 0, j = 0, k = 0;

	for (i = 0; i < 10; i++) {
		k = i * a;
		for (j = 1; j < 5; j++) {
			result += k + j;
		}
	}
	return result;
}

i4 pcode_testNestedLoop2(i4 a)
{
	i4 result = 0;
	i4 i = 0, j = 0, k = 1;

	for (i = 0; i < 10; i++) {
		for (j = 1; j < 5; j++) {
			result += a * (k + j);
		}
		k = i + 2;
	}
	return result;
}

i4 pcode_testNestedLoop3(i4 a)
{
	i4 result = 0;
	i4 i = 0, j = 0, k = 1;

	for (i = 0; i < 10; i++) {
		k += 1;
		for (j = 1; j < 5; j++) {
			result += a * (k + j);
		}
		k *= 2;
	}
	return result;
}
