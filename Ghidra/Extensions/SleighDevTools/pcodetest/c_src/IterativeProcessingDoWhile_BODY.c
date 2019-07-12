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

i4 pcode_StandardPostIncDoWhileLoop()
{
	i4 ii = 0;
	i4 accum = 0;

	do {
		accum += 5;
	} while (ii++ < 5);
	return accum;
}

i4 pcode_StandardPreIncDoWhileLoop()
{
	i4 ii = 0;
	i4 accum = 0;

	do {
		accum += 5;
	} while (++ii <= 5);
	return accum;
}

i4 pcode_StandardPostDecDoWhileLoop()
{
	i4 ii = 5;
	i4 accum = 0;

	do {
		accum += 5;
	} while (ii-- > 0);
	return accum;
}

i4 pcode_StandardPreDecDoWhileLoop()
{
	i4 ii = 5;
	i4 accum = 0;

	do {
		accum += 5;
	} while (--ii >= 0);
	return accum;
}

i4 pcode_VarIncrementPostIncDoWhileLoop(i4 kk)
{
	i4 ii = 0;
	i4 accum = 0;

	do {
		accum += kk;
	} while (ii++ < 5);
	return accum;
}

i4 pcode_VarIncrementPreIncDoWhileLoop(i4 kk)
{
	i4 ii = 0;
	i4 accum = 0;

	do {
		accum += kk;
	} while (++ii <= 5);
	return accum;
}

i4 pcode_VarIncrementPostDecDoWhileLoop(i4 kk)
{
	i4 ii = 5;
	i4 accum = 0;

	do {
		accum += kk;
	} while (ii-- > 0);
	return accum;
}

i4 pcode_VarIncrementPreDecDoWhileLoop(i4 kk)
{
	i4 ii = 5;
	i4 accum = 0;

	do {
		accum += kk;
	} while (--ii >= 0);
	return accum;
}

i4 pcode_VarIterationPostIncDoWhileLoop(i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;

	do {
		accum += 5;
	} while (ii++ < nn);
	return accum;
}

i4 pcode_VarIterationPreIncDoWhileLoop(i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;

	do {
		accum += 5;
	} while (++ii <= nn);
	return accum;
}

i4 pcode_VarIterationPostDecDoWhileLoop(i4 nn)
{
	i4 ii = nn;
	i4 accum = 0;

	do {
		accum += 5;
	} while (ii-- > 0);
	return accum;
}

i4 pcode_VarIterationPreDecDoWhileLoop(i4 nn)
{
	i4 ii = nn;
	i4 accum = 0;

	do {
		accum += 5;
	} while (--ii >= 0);
	return accum;
}

i4 pcode_VariablePostIncDoWhileLoop(i4 kk, i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;

	do {
		accum += kk;
	} while (ii++ < nn);
	return accum;
}

i4 pcode_VariablePreIncDoWhileLoop(i4 kk, i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;

	do {
		accum += kk;
	} while (++ii <= nn);
	return accum;
}

i4 pcode_VariablePostDecDoWhileLoop(i4 kk, i4 nn)
{
	i4 ii = nn;
	i4 accum = 0;

	do {
		accum += kk;
	} while (ii-- > 0);
	return accum;
}

i4 pcode_VariablePreDecDoWhileLoop(i4 kk, i4 nn)
{
	i4 ii = nn;
	i4 accum = 0;

	do {
		accum += kk;
	} while (--ii >= 0);
	return accum;
}

i4 pcode_SwitchedDoWhileLoop(i4 type, i4 kk, i4 jj, i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;

	do {
		if (type == 10) {
			accum += kk;
		} else {
			accum += jj;
		}
	} while (ii++ < nn);
	return accum;
}

i4 pcode_UnSwitchedDoWhileLoop(i4 type, i4 kk, i4 jj, i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;

	if (type == 10) {
		do {
			accum += kk;
		} while (ii++ < nn);
	} else {
		do {
			accum += jj;
		} while (ii++ < nn);
	}
	return accum;
}

i4 pcode_JammedDoWhileLoop(i4 kk, i4 jj, i4 nn)
{
	i4 ii = 0;
	i4 accum1 = 0;
	i4 accum2 = 0;

	do {
		accum1 += kk;
		accum2 += jj;
	} while (ii++ < nn);
	return (accum1 << 16) | accum2;
}

i4 pcode_UnJammedDoWhileLoop(i4 kk, i4 jj, i4 nn)
{
	i4 ii = 0;
	i4 accum1 = 0;
	i4 accum2 = 0;

	do {
		accum1 += kk;
	} while (ii++ < nn);
	ii = 0;
	do {
		accum2 += jj;
	} while (ii++ < nn);
	return (accum1 << 16) | accum2;
}

i4 pcode_RolledDoWhileLoop(i4 array[], i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;

	do {
		accum += array[ii++];
	} while (ii < nn);
	return accum;
}

i4 pcode_Unrolled2DoWhileLoop(i4 array[], i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;
	i4 limit = nn & (~1);

	do {
		accum += array[ii] + array[ii + 1];
		ii += 2;
	} while (ii < limit);
	if (limit != nn) {
		accum += array[ii];
	}
	return accum;
}

i4 pcode_Unrolled4DoWhileLoop(i4 array[], i4 nn)
{
	i4 ii = 0;
	i4 accum = 0;
	i4 limit = nn & (~3);

	do {
		accum += array[ii] + array[ii + 1] + array[ii + 2] + array[ii + 3];
		ii += 4;
	} while (ii < limit);
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
