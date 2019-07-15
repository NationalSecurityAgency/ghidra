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

i4 pcode_StandardPostIncWhileLoop()
{
	i4 ii = 0;
	i4 accum = 0;

	while (ii++ < 5) {
		accum += 5;
	}
	return accum;
}

i4 pcode_StandardPreIncWhileLoop()
{
	i4 ii = 0;
	i4 accum = 0;

	while (++ii <= 5) {
		accum += 5;
	}
	return accum;
}

i4 pcode_StandardPostDecWhileLoop()
{
	i4 ii = 5;
	i4 accum = 0;

	while (ii-- > 0) {
		accum += 5;
	}
	return accum;
}

i4 pcode_StandardPreDecWhileLoop()
{
	i4 ii = 5;
	i4 accum = 0;

	while (--ii >= 0) {
		accum += 5;
	}
	return accum;
}

i4 pcode_VarIncrementPostIncWhileLoop(i4 kk)
{
	i4 ii = 0;
	i4 accum = 0;

	while (ii++ < 5) {
		accum += kk;
	}
	return accum;
}

i4 pcode_VarIncrementPreIncWhileLoop(i4 kk)
{
	i4 ii = 0;
	i4 accum = 0;

	while (++ii <= 5) {
		accum += kk;
	}
	return accum;
}

i4 pcode_VarIncrementPostDecWhileLoop(i4 kk)
{
	i4 ii = 5;
	i4 accum = 0;

	while (ii-- > 0) {
		accum += kk;
	}
	return accum;
}

i4 pcode_VarIterationPostIncWhileLoop(i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;

	while (ii++ < nn) {
		accum += 5;
	}
	return accum;
}

i4 pcode_VarIncrementPreDecWhileLoop(i4 kk)
{
	i4 ii = 5;
	i4 accum = 0;

	while (--ii >= 0) {
		accum += kk;
	}
	return accum;
}

i4 pcode_VarIterationPreIncWhileLoop(i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;

	while (++ii <= nn) {
		accum += 5;
	}
	return accum;
}

i4 pcode_VarIterationPostDecWhileLoop(i4 nn)
{
	i4 ii = nn;
	i4 accum = 0;

	while (ii-- > 0) {
		accum += 5;
	}
	return accum;
}

i4 pcode_VarIterationPreDecWhileLoop(i4 nn)
{
	i4 ii = nn;
	i4 accum = 0;

	while (--ii >= 0) {
		accum += 5;
	}
	return accum;
}

i4 pcode_VariablePostIncWhileLoop(i4 kk, i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;

	while (ii++ < nn) {
		accum += kk;
	}
	return accum;
}

i4 pcode_VariablePreIncWhileLoop(i4 kk, i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;

	while (++ii <= nn) {
		accum += kk;
	}
	return accum;
}

i4 pcode_VariablePostDecWhileLoop(i4 kk, i4 nn)
{
	i4 ii = nn;
	i4 accum = 0;

	while (ii-- > 0) {
		accum += kk;
	}
	return accum;
}

i4 pcode_VariablePreDecWhileLoop(i4 kk, i4 nn)
{
	i4 ii = nn;
	i4 accum = 0;

	while (--ii >= 0) {
		accum += kk;
	}
	return accum;
}

i4 pcode_UnSwitchedWhileLoop(i4 type, i4 kk, i4 jj, i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;

	if (type == 10) {
		while (ii++ < nn) {
			accum += kk;
		}
	} else {
		while (ii++ < nn) {
			accum += jj;
		}
	}
	return accum;
}

i4 pcode_SwitchedWhileLoop(i4 type, i4 kk, i4 jj, i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;

	while (ii++ < nn) {
		if (type == 10) {
			accum += kk;
		} else {
			accum += jj;
		}
	}
	return accum;
}

i4 pcode_JammedWhileLoop(i4 kk, i4 jj, i4 nn)
{
	i4 ii = 0;
	i4 accum1 = 0;
	i4 accum2 = 0;

	while (ii++ < nn) {
		accum1 += kk;
		accum2 += jj;
	}
	return (accum1 << 16) | accum2;
}

i4 pcode_UnJammedWhileLoop(i4 kk, i4 jj, i4 nn)
{
	i4 ii = 0;
	i4 accum1 = 0;
	i4 accum2 = 0;

	while (ii++ < nn) {
		accum1 += kk;
	}
	ii = 0;
	while (ii++ < nn) {
		accum2 += jj;
	}
	return (accum1 << 16) | accum2;
}

i4 pcode_RolledWhileLoop(i4 array[], i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;

	while (ii < nn) {
		accum += array[ii++];
	}
	return accum;
}

i4 pcode_Unrolled2WhileLoop(i4 array[], i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;
	i4 limit = nn & (~1);

	while (ii < limit) {
		accum += array[ii] + array[ii + 1];
		ii += 2;
	}
	if (limit != nn) {
		accum += array[ii];
	}
	return accum;
}

i4 pcode_Unrolled4WhileLoop(i4 array[], i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;
	i4 limit = nn & (~3);

	while (ii < limit) {
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
