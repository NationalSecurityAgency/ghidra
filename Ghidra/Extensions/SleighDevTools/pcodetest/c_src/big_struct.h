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

/* A struct to use in testing */

typedef struct big_struct
{
#ifdef HAS_LONGLONG
	long long ll;
#else
	char ll[8];
#endif
	int i;
	short s;
	char c;
#ifdef HAS_LONGLONG
	unsigned long long ull;
#else
	char ull[8];
#endif
	unsigned int ui;
	unsigned short us;
	unsigned char uc;
#ifdef HAS_FLOAT
	float f;
#else
	char f[4];
#endif
#ifdef HAS_DOUBLE
	double d;
#else
	char d[8];
#endif
	struct big_struct *b;
} big_struct_type;

typedef union big_union
{
#ifdef HAS_LONGLONG
	long long ll;
#else
	char ll[8];
#endif
	int i;
	short s;
	char c;
#ifdef HAS_LONGLONG
	unsigned long long ull;
#else
	char ull[8];
#endif
	unsigned int ui;
	unsigned short us;
	unsigned char uc;
#ifdef HAS_FLOAT
	float f;
#else
	char f[4];
#endif
#ifdef HAS_DOUBLE
	double d;
#else
	char d[8];
#endif
	union big_union *b;
} big_union_type;

