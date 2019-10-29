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

#ifndef HAS_LIBC
void *memcpy(void *dest, const void *src, size_t n)
{
	unsigned i;
	for (i = 0; i < n; i++)
		((unsigned char *) dest)[i] = ((unsigned char *) src)[i];
	return dest;
}
#endif // !HAS_LIBC

#ifndef HAS_LIBC
void *memset(void *s, int c, size_t n)
{
	unsigned char *dst = s;
	for (; n > 0; n--, dst++)
		*dst = (unsigned char) c;
	return s;
}
#endif // !HAS_LIBC

#ifndef HAS_LIBC
int memcmp(void *s1, void *s2, size_t n)
{
	unsigned i;
	for (i = 0; i < n; i++, s1++, s2++) {
		if (* (unsigned char *) s1 < * (unsigned char *) s2) return -1;
		else if (* (unsigned char *) s1 > * (unsigned char *) s2) return 1;
	}
	return 0;
}
#endif // !HAS_LIBC

#if defined(BUILD_EXE)

#pragma GCC push_options
#pragma GCC optimize("O0")

#ifndef HAS_LIBC
void write(int fd, char *buf, int count)
{
#if defined(__AARCH64EL__) || defined(__AARCH64EB__)
	asm(	"mov x0,%[fd]\n\t"
		"mov x1,%[msgstr]\n\t"
		"mov x2,%[msglen]\n\t"
		"mov x8,#64\n\t"
		"svc #0\n\t"
		:
		: [fd] "r" (fd),
		  [msgstr] "r" (buf),
		  [msglen] "r" (count)
		: "x0", "x1", "x2", "x8"
	);

#elif defined(__ARM_ARCH_ISA_THUMB)
	asm(	"push {r7}\n\t"
		"mov r0,%[fd]\n\t"
		"mov r1,%[msgstr]\n\t"
		"mov r2,%[msglen]\n\t"
		"mov r7,#4\n\t"
		"swi #0\n\t"
		"pop {r7}\n\t"
		:
		: [fd] "r" (fd),
		  [msgstr] "r" (buf),
		  [msglen] "r" (count)
		: "r0", "r1", "r2"
	);


#elif defined(__ARMEL__) || defined(__ARMEB__)
	asm(	"mov %%r0,%[fd]\n\t"
		"mov %%r1,%[msgstr]\n\t"
		"mov %%r2,%[msglen]\n\t"
		"mov %%r7,#4\n\t"
		"swi $0\n\t"
		:
		: [fd] "r" (fd),
		  [msgstr] "r" (buf),
		  [msglen] "r" (count)
		: "r0", "%r1", "r2", "r7"
	);

#elif defined(__m68k__)
	asm(	"moveq #4,%%d0\n\t"
		"move %[fd],%%d1\n\t"
		"move %[msgstr],%%d2\n\t"
		"move %[msglen],%%d3\n\t"
		"trap #0\n\t"
		:
		: [fd] "r" (fd),
		  [msgstr] "r" (buf),
		  [msglen] "r" (count)
		: "d0", "d1", "d2", "d3"
	);

#elif defined(__MIPSEB__)
	asm(	"move $a0, %[fd]\n\t"
		"move $a1, %[msgstr]\n\t"
		"move $a2, %[msglen]\n\t"
		"li $v0, 4004\n\t"
		"syscall\n\t"
		:
		: [fd] "r" (fd),
		  [msgstr] "r" (buf),
		  [msglen] "r" (count)
		: "v0", "a0", "a1", "a2"
	);

#elif defined(__PPC__)
	asm(	"li 0,4\n\t"
		"lwz 3,%[fd]\n\t"
#ifdef __PPC64__
		"ld 4,%[msgstr]\n\t"
#else
		"lwz 4,%[msgstr]\n\t"
#endif
		"lwz 5,%[msglen]\n\t"
		"sc\n\t"
		:
		: [fd] "" (fd),
		  [msgstr] "" (buf),
		  [msglen] "" (count)
		: "r0", "r3", "r4", "r5"
	);

#elif defined(__pentium__)
	asm(	"mov %[msglen],%%edx\n\t"
		"mov %[msgstr],%%ecx\n\t"
		"mov %[fd],%%ebx\n\t"
		"mov $4,%%eax\n\t"
		"int $0x80\n\t"
		:
		: [fd] "" (fd),
		  [msgstr] "" (buf),
		  [msglen] "" (count)
		: "eax", "ebx", "ecx", "edx"
	);

#elif defined(__SH4__)
	asm(	"mov #4,r3\n\t"
		"mov %[fd],r4\n\t"
		"mov %[msgstr],r5\n\t"
		"mov %[msglen],r6\n\t"
		"trapa #17\n\t"
		:
		: [fd] "r" (fd),
		  [msgstr] "r" (buf),
		  [msglen] "r" (count)
		: "r3", "r4", "r5", "r6"
	);

#elif defined(__sparc__)
	asm(	"mov 1,%%o0\n\t"
		// "sethi %%hi(%[msgstr]), %%g1\n\t"
		// "or %%g1, %%lo(%[msgstr]), %%o1\n\t"
		"ld %[msgstr], %%o1\n\t"
		"mov 4,%%g1\n\t"
		"ld %[msglen],%%o2\n\t"
		"t 0x6d\n\t"
		:
		: [fd] "" (fd),
		  [msgstr] "" (buf),
		  [msglen] "" (count)
		: "o0", "g1", "o1", "o2"
	);

#elif defined(__x86_64__)
	asm(	"mov %[msglen],%%edx\n\t"
		"movq %[msgstr],%%rsi\n\t"
		"movq %[fd],%%rdi\n\t"
		"movq $1,%%rax\n\t"
		"syscall\n\t"
		:
		: [fd] "" (fd),
		  [msgstr] "" (buf),
		  [msglen] "" (count)
		: "rax", "rdi", "rsi", "rdx"
	);
#endif
}
#endif // !HAS_LIBC

#ifndef HAS_LIBC
void exit(int stat)
{
#if defined(__AARCH64EL__) || defined(__AARCH64EB__)
	asm(	"mov x0,%[status]\n\t"
		"mov x8,#93\n\t"
		"svc #0\n\t"
		:
		: [status] "r" (stat)
		: "x0", "x8"
	);

#elif defined(__ARM_ARCH_ISA_THUMB)
	asm(	"push {r7}\n\t"
		"mov r0,%[status]\n\t"
		"mov r7,#1\n\t"
		"swi #0\n\t"
		"pop {r7}\n\t"
		:
		: [status] "r" (stat)
		: "r0"
	);

#elif defined(__ARMEL__) || defined(__ARMEB__)
	asm(	"mov %%r0,%[status]\n\t"
		"mov %%r7,#1\n\t"
		"swi $0\n\t"
		:
		: [status] "r" (stat)
		: "r0", "r7"
	);

#elif defined(__m68k__)
	asm(	"moveq #1,%%d0\n\t"
		"move %[status],%%d1\n\t"
		"trap #0\n\t"
		:
		: [status] "" (stat)
		: "d0", "d1"
	);

#elif defined(__MIPSEB__)
	asm(	"move $a0,%[status]\n\t"
		"li $v0, 4001\n\t"
		"syscall\n\t"
		:
		: [status] "r" (stat)
		: "v0", "a0"
	);

#elif defined(__PPC__)
	asm(	" li 0,1 \n"
		" lwz 3,%[status] \n"
		" sc \n"
		:
		: [status] "" (stat)
		: "r0", "r3"
	);

#elif defined(__pentium__)
	asm(	"mov %[status],%%ebx\n\t"
		"mov $1,%%eax\n\t"
		"int $0x80\n\t"
		:
		: [status] "" (stat)
		: "eax", "ebx"
	);

#elif defined(__SH4__)
	asm(	"mov #1,r3\n\t"
		"mov %[status],r4\n\t"
		"trapa #17\n\t"
		:
		: [status] "r" (stat)
		: "r3", "r4"
	);

#elif defined(__sparc__)
	asm(	"mov 1,%%g1\n\t"
		"mov %[status],%%o0\n\t"
		"t 0x6d\n\t"
		"nop\n\t"
		:
		: [status] "r" (stat)
		: "g1", "o0"
	);

#elif defined(__x86_64__)
	asm(	"mov %[status],%%rdi\n\t"
		"mov $60,%%rax\n\t"
		"syscall\n\t"
		:
		: [status] "" (stat)
		: "rax", "rdi"
	);
#endif
}
#endif // !HAS_LIBC

#ifndef HAS_LIBC
static int strlen(char *str)
{
	int len;
	for (len = 0; str[len]; len++) ;
	return len;
}
#endif // !HAS_LIBC

#ifndef HAS_LIBC
static void strcpy(char *dst, char *src)
{
	while (*src) *dst++ = *src++;
	*dst = *src;
}
#endif // !HAS_LIBC

#ifndef HAS_LIBC
static void put(char *str)
{
	write(1, str, strlen(str));
}
#endif // !HAS_LIBC

// utoa, itoa and ftoa

// Convert unsigned u to decimal.
// if dflag is set, insert a decimal point after the first nonzero
// digit, and return the number of decimal places

static int utoa(unsigned long u, char *buff, int len, int dflag)
{
	int i = len - 1;
	int ret = 0;
	int j;

	if (dflag) dflag = 1;

	if (u == 0) {
		if (dflag) {
			strcpy(buff, "0.0");
			return 1;
		} else {
			strcpy(buff, "0");
			return 0;
		}
	}

	// Put in ascii at the end of the buffer

	buff[i] = '\0';
	i = i - 1;
	while (u > 0 && i >= 0) {
		buff[i] = '0' + (u % 10);
		u = u / 10;
		i = i - 1;
	}

	// Now move the string to the front of the buffer, optionally
	// inserting a decimal point

	j = 0;
	i = i + 1;
	while (i < len && j < i) {
		if (j == 1 && dflag) {
			buff[j] = '.';
			j = j + 1;
		}
		buff[j] = buff[i];
		if (dflag && j > 1 && buff[j]) ret = ret + 1;
		j = j + 1;
		i = i + 1;
	}

	return ret;
}

static int itoa(long u, char *buff, int len, int dflag)
{
	if (u < 0) {
		*buff = '-';
		len = len - 1;
		buff = buff + 1;
		u = - u;
	}
	utoa(u, buff, len, dflag);
}

static void ftoa(float f, char *buff, int len)
{
	unsigned int fi;
	int sig;
	unsigned int f2, fa;
	int e2, ea;
	int ra;

	*buff = '\0';

	// find fa and ea such that
	// f = f2 2^(e2-23) = fa 10^ea

	if (sizeof(f) == 4) {
		fi = * (int *) &f;
		sig = (fi & 0x80000000) ? 1 : 0;
		e2 = ((fi >> 23) & 0xff);
		f2 = (fi & 0x7fffff);

		// Handle normalized numbers

		if (e2 != 0) {
			f2 = f2 | 0x800000;
			e2 = e2 - 127;
			e2 = e2 - 23;
		}

		if (e2 == 0 && f2 == 0) {
			strcpy(buff, "0.0");
			return;
		}

		// determine ea, fa iteratively
		// by reducing e2 to 0

		ea = 0;
		fa = f2;
		// printf("%f = %u 2^%d 10^%d?\n", f, fa, e2, ea);
		while (e2 > 0) {
			// If the the high bit is set
			// then we can't multiply by 2
			// without losing it, so divide by 10
			// and round off
			if (fa & (1 << 31)) {
				ra = ((fa % 5) > 2) ? 1 : 0;
				fa = (fa / 5) + ra;
				ea = ea + 1;
			} else {
				fa = fa * 2;
			}
			e2 = e2 - 1;
			// printf("%f = %u 2^%d 10^%d?\n", f, fa, e2, ea);
		}
		while (e2 < 0) {
			// If the top 3 bits are zero
			// then we can multiply by 10
			// and preserve the precision
			if ((fa & (7 << 29)) == 0) {
				fa = fa * 5;
				ea = ea - 1;
			} else {
				ra = (fa % 2) ? 1 : 0;
				fa = (fa / 2) + ra;
			}
			e2 = e2 + 1;
			// printf("%f = %u 2^%d 10^%d?\n", f, fa, e2, ea);
		}

		// Now we have what we want, f = fa 10^ea
		// it remains to convert this to ascii
		// and move the decimal point

		if (sig) {
			*buff = '-';
			len = len - 1;
			buff = buff + 1;
		}
		ea = ea + utoa(fa, buff, len, 1);
		len = len - strlen(buff);
		buff = buff + strlen(buff);
		if (ea == 0) return;

		*buff = 'e';
		len = len - 1;
		buff = buff + 1;

		if (ea < 0) {
			*buff = '-';
			len = len - 1;
			buff = buff + 1;
			ea = -ea;
		} else {
			*buff = '+';
			len = len - 1;
			buff = buff + 1;
		}
		utoa(ea, buff, len, 0);
	}
}

static void print_info(char *file, int line, char *func, char *type, char *expected, char *val, char *ok)
{
#ifndef HAS_LIBC
	char lbuff[100];
	utoa(line, lbuff, 100, 0);

	put("File "); put(file);
	put(" line "); put(lbuff);
	put(" function "); put(func);
	put(" expected "); put(type);
	put(" "); put(expected);
	put(" got "); put(val);
	put(" "); put(ok);
	put("\n");
#else
	printf("File %s line %d function %s expected %s %s got %s %s\n", file, line, func, type, expected, val, ok);
#endif // HAS_LIBC
}

void print_int(char *file, int line, char *func, int expected, int val, char *ok)
{
#ifdef HAS_PRINTF
	printf("File %s line %d function %s expected %s %d got %d %s\n", file, line, func, "int", expected, val, ok);
#else
	char ebuff[100];
	itoa(expected, ebuff, 100, 0);
	char vbuff[100];
	itoa(val, vbuff, 100, 0);
	print_info(file, line, func, "int", ebuff, vbuff, ok);
#endif
}

void print_long(char *file, int line, char *func, long expected, long val, char *ok)
{
#ifdef HAS_PRINTF
	printf("File %s line %d function %s expected %s %ld got %ld %s\n", file, line, func, "long", expected, val, ok);
#else
	char ebuff[100];
	itoa(expected, ebuff, 100, 0);
	char vbuff[100];
	itoa(val, vbuff, 100, 0);
	print_info(file, line, func, "long", ebuff, vbuff, ok);
#endif
}

void print_uint(char *file, int line, char *func, unsigned int expected, unsigned int val, char *ok)
{
#ifdef HAS_PRINTF
	printf("File %s line %d function %s expected %s %u got %u %s\n", file, line, func, "uint", expected, val, ok);
#else
	char ebuff[100];
	utoa(expected, ebuff, 100, 0);
	char vbuff[100];
	utoa(val, vbuff, 100, 0);
	print_info(file, line, func, "uint", ebuff, vbuff, ok);
#endif
}

void print_ulong(char *file, int line, char *func, unsigned long expected, unsigned long val, char *ok)
{
#ifdef HAS_PRINTF
	printf("File %s line %d function %s expected %s %lu got %lu %s\n", file, line, func, "ulong", expected, val, ok);
#else
	char ebuff[100];
	utoa(expected, ebuff, 100, 0);
	char vbuff[100];
	utoa(val, vbuff, 100, 0);
	print_info(file, line, func, "ulong", ebuff, vbuff, ok);
#endif
}

void print_float(char *file, int line, char *func, float expected, float val, char *ok)
{
#ifdef HAS_PRINTF
	printf("File %s line %d function %s expected %s %.9e got %.9e %s\n", file, line, func, "float", expected, val, ok);
#else
	char ebuff[100];
	char vbuff[100];
	ftoa(expected, ebuff, 100);
	ftoa(val, vbuff, 100);
	print_info(file, line, func, "float", ebuff, vbuff, ok);
#endif
}

void print_val(char *name, int val)
{
#ifdef HAS_PRINTF
	printf("%s %d\n", name, val);
#else
	char vbuff[100];
	itoa(val, vbuff, 100, 0);
	put(name); put(" "); put(vbuff); put("\n");
#endif
}

#pragma GCC pop_options
#endif // BUILD_EXE
