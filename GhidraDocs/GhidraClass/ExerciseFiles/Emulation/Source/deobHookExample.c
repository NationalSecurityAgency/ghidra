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
#ifdef __x86_64

#include <malloc.h>
#include <string.h>

#else

// Library routine not linked in for cross-build

void * malloc(int size) {
	// missing implementation
	return (void *)0;
}

void free(void *ptr) {
	// missing implementation
}

int strlen(char *s) {
	int len = 0;
	while (*s++ != 0) {
		++len;
	}
	return len;
}

#endif

const char data[] = {
0xec,
0xc3,
0xd8,
0xd9,
0xde,
0x8a,
0xcf,
0xc4,
0xde,
0xd8,
0xd3,
0x00,
0xf9,
0xcf,
0xc9,
0xc5,
0xc4,
0xce,
0x8a,
0xcf,
0xc4,
0xde,
0xd8,
0xd3,
0x00,
0xfe,
0xc2,
0xc3,
0xd8,
0xce,
0x8a,
0xcf,
0xc4,
0xde,
0xd8,
0xd3,
0x00,
0x00
};

char * deobfuscate(char *src, int len) {
        char *buf = (char *)malloc(len + 1);
        char *ptr = buf;
        for (int i = 0; i < len; i++) {
            *ptr++ = *src++ ^ 0xAA;
        }
        *ptr = 0;
        return buf;
}

void use_string(char * str, int index) {
//	fprintf(stderr, "String[%d]: %s\n", index, str);
}

int main (int argc, char **argv) {
    char *ptr = (char *)data;
    int index = 0;
    while (*ptr != 0) {
        int len = strlen(ptr);
        char *str = deobfuscate(ptr, len);
	use_string(str, index++);
        free(str);
	ptr += len + 1;
    }
    return 0;
}

#ifndef __x86_64


int _start() {
	char *argv[] = { "deobExample" };
	return main(1, argv);
}

#endif
