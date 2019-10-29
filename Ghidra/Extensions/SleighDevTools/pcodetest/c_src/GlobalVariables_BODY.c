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

extern i4 GLOBAL = 0;

void pcode_ModifyGlobal(i4 arg1)
{
	GLOBAL = arg1;
}

i4 pcode_AccessAndModifyGlobal(i4 arg1)
{
	i4 tmp;

	tmp = GLOBAL;
	GLOBAL = arg1;
	return tmp;
}

i4 pcode_AccessGlobal()
{
	return GLOBAL;
}
