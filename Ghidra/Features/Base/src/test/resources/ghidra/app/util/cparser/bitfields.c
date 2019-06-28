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
#include <stdio.h>
#include "bitfields.h"

struct A1 A1 = { { 5, 0xa, 5, 0xa, 5}, 3, 0xAA, 0x55, 0x3f };

struct A2 A2 = { { 5, 0x050a050a }, 3, 0xAA, 0x55, 0x3f };


struct B1 B1 = { 5, 0x2A, -1, 0xA };

struct B2 B2 = { 5, 0x2A, -1, 0xA };

struct B3 B3 = { 5, 0x2A, -1, 0xA };


struct Z1 Z1 = { 5, 0x2A, -1, 0xA };

struct Z2 Z2 = { 5, 0x2A, -1, 0xA };

struct Z3 Z3 = { 5, 0x2A, -1, 0xA };

struct Z4 Z4 = { 5, 0x2A, -1, 0xA };

struct Z5 Z5 = { 5, 0x2A, -1, 0xA };

struct Z6 Z6 = { 5, 0x2A, -1, 0xA, 0x2A, -1, 0xA };


struct B1p1 B1p1 = { 5, 0x2A, -1, 0xA };

struct B2p1 B2p1 = { 5, 0x2A, -1, 0xA };

struct B3p1 B3p1 = { 5, 0x2A, -1, 0xA };


struct Z1p1 Z1p1 = { 5, 0x2A, -1, 0xA };

struct Z2p1 Z2p1 = { 5, 0x2A, -1, 0xA };

struct Z3p1 Z3p1 = { 5, 0x2A, -1, 0xA };
struct Z3p1T Z3p1T = { 7, { 5, 0x2A, -1, 0xA }};

struct Z4p1 Z4p1 = { 5, 0x2A, -1, 0xA };


struct B1p2 B1p2 = { 5, 0x2A, -1, 0xA };

struct B2p2 B2p2 = { 5, 0x2A, -1, 0xA };

struct B3p2 B3p2 = { 5, 0x2A, -1, 0xA };

struct B4p2 B4p2 = { 5, 0x2A, -1, 0x5555555555555555, 0xA };


struct Z1p2 Z1p2 = { 5, 0x2A, -1, 0xA };

struct Z1p2x Z1p2x = { 5, 0x2A, -1, 0xA, -1, 0, -1, 0, -1, 0, -1,   0x2A, -1, 0xA, -1, 0, -1, 0, -1, 0, -1 };

struct Z2p2 Z2p2 = { 5, 0x2A, -1, 0xA };

struct Z3p2 Z3p2 = { 5, 0x2A, -1, 0xA };

struct Z4p2 Z4p2 = { 5, 0x2A, -1, 0xA };

struct Z5p2 Z5p2 = { 5, 0x2A, -1, 0xA };

struct x1p2 x1p2 = { 5 };

struct x2p2 x2p2 = { 5, 0x2A };

struct x3p2 x3p2 = { 5, 0x2A };

struct x4p2 x4p2 = { 5, 0x2A };


struct Z5p4 Z5p4 = { 5, 0x2A, -1, 0xA };

struct x1p4 x1p4 = { 5 };

struct x2p4 x2p4 = { 5, 0x2A };

struct x3p4 x3p4 = { 5, 0x2A };

struct x4p4 x4p4 = { 5, 0x2A };


struct S1 S1 = { { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA } };


struct S1p1 S1p1 = { { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA } };

struct S2p1 S2p1 = { { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA } };


struct S1p2 S1p2 = { { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA } };

struct S2p2 S2p2 = { { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA }, { 5, 0x2A, -1, 0xA } };

struct T1 T1 = { 5, TWO, THREE, 1 };

struct T2 T2 = { 5, 0x2A, THREE, 1 };

union U1 U1;
union U1z U1z;
union U1p1 U1p1;
union U1p1z U1p1z;
union U1p2 U1p2;

struct SUp1 SUp1;

int main(int argc, char *argv[]) {
        printf("len B1: %d\n", sizeof(struct B1));
        printf("len B2: %d\n", sizeof(struct B2));
        printf("len B3: %d\n", sizeof(struct B3));

        printf("len Z1: %d\n", sizeof(struct Z1));
        printf("len Z2: %d\n", sizeof(struct Z2));
        printf("len Z3: %d\n", sizeof(struct Z3));
        printf("len Z4: %d\n", sizeof(struct Z4));
        printf("len Z5: %d\n", sizeof(struct Z5));
        printf("len Z6: %d\n", sizeof(struct Z6));

        printf("len B1p1: %d\n", sizeof(struct B1p1));
        printf("len B2p1: %d\n", sizeof(struct B2p1));
        printf("len B3p1: %d\n", sizeof(struct B3p1));

        printf("len Z1p1: %d\n", sizeof(struct Z1p1));
        printf("len Z2p1: %d\n", sizeof(struct Z2p1));
        printf("len Z3p1: %d\n", sizeof(struct Z3p1));
        printf("len Z3p1T: %d\n", sizeof(struct Z3p1T));
        printf("len Z4p1: %d\n", sizeof(struct Z4p1));

        printf("len B1p2: %d\n", sizeof(struct B1p2));
        printf("len B2p2: %d\n", sizeof(struct B2p2));
        printf("len B3p2: %d\n", sizeof(struct B3p2));
        printf("len B4p2: %d\n", sizeof(struct B4p2));

        printf("len Z1p2: %d\n", sizeof(struct Z1p2));
        printf("len Z1p2x: %d\n", sizeof(struct Z1p2x));
        printf("len Z2p2: %d\n", sizeof(struct Z2p2));
        printf("len Z3p2: %d\n", sizeof(struct Z3p2));
        printf("len Z4p2: %d\n", sizeof(struct Z4p2));
        printf("len Z5p2: %d\n", sizeof(struct Z5p2));
        printf("len x1p2: %d\n", sizeof(struct x1p2));
        printf("len x2p2: %d\n", sizeof(struct x2p2));
        printf("len x3p2: %d\n", sizeof(struct x3p2));
        printf("len x4p2: %d\n", sizeof(struct x4p2));

	printf("len Z5p4: %d\n", sizeof(struct Z5p4));
	printf("len x1p4: %d\n", sizeof(struct x1p4));
        printf("len x2p4: %d\n", sizeof(struct x2p4));
        printf("len x3p4: %d\n", sizeof(struct x3p4));
        printf("len x4p4: %d\n", sizeof(struct x4p4));

        printf("len S1: %d\n", sizeof(struct S1));

        printf("len S1p1: %d\n", sizeof(struct S1p1));
        printf("len S2p1: %d\n", sizeof(struct S2p1));

        printf("len S1p2: %d\n", sizeof(struct S1p2));
        printf("len S2p2: %d\n", sizeof(struct S2p2));
        
        printf("len T1: %d\n", sizeof(struct T1));
        printf("len T2: %d\n", sizeof(struct T2));

	printf("len U1: %d\n", sizeof(union U1));
	printf("len U1z: %d\n", sizeof(union U1z));
	printf("len U1p1: %d\n", sizeof(union U1p1));
	printf("len U1p1z: %d\n", sizeof(union U1p1z));
	printf("len U1p2: %d\n", sizeof(union U1p2));

	printf("len SUp1: %d\n", sizeof(struct SUp1));
}
