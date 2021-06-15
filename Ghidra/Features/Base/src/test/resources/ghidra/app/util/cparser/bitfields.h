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
// Verify bitfield grouping and alignment without zero-length bitfields

#pragma pack(1)

struct oddStruct {
        char x;
        int  y;
};

#pragma pack()

struct A1 {
        char a[5]; // test for alignment overlap (gcc)
        int b:3;
        int c:8;
        int d:8;
        int e:6;
};

struct A2 {
        struct oddStruct a; // test for check alignment overlap (gcc)
        int b:3;
        int c:8;
        int d:8;
        int e:6;
};

struct A3 {
        char a[5]; // test for alignment overlap (gcc)
        int b:3;
        int c:8;
        int d:85;  // test oversized bitfield
        int e:6;
};

struct B1 {
	char a;
	unsigned short b:6; // gcc groups with previous non-bitfield
	int c:8; // gcc groups with previous two fields (including non-bitfield)
	short d:4;
};

struct B1flex {
	char a;
	unsigned short b:6; // gcc groups with previous non-bitfield
	int c:8; // gcc groups with previous two fields (including non-bitfield)
	short d:4;
	long flex[];
};  

struct B2 {
	char a;
	unsigned short b:6; // gcc groups with previous non-bitfield
	int c:8;
	int d:4;
}; 

struct B3 {
	char a;
	unsigned short b:6; // gcc groups with previous non-bitfield
	int c:8;
	char d; // gcc groups with int bit-field
}; 



// Verify bitfield grouping and alignment with zero-length bitfields

struct Z1 {
	char a;
	int :0; // MSVC ignores field, gcc forces break and does not combine with previous field
	unsigned short b:6;
	int c:8;
	short d:4;
}; 

struct Z2 {
	char a;
	unsigned short b:6; // gcc groups with previous non-bitfield
	int c:8;
	int :0;
	short d:4;
}; 

struct Z3 {
	char a;
	unsigned short b:6; // gcc groups with previous non-bitfield
	int c:8; // gcc groups with previous two fields (including non-bitfield)
	int d:4;
	long long :0; // trailing :0 imposes alignment onto structure
}; 

struct Z4 {
	char a;
	unsigned short b:6; // gcc groups with previous non-bitfield
	int c:8;    // gcc groups with previous two fields (including non-bitfield)
	long long :0; // forced alignment of non-bitfield
	char d;
}; 

struct Z5 {
	char a;
	int :0;
	long long b:6;
	int c:8;
	char d;
};

struct Z6 {
	char a;
	int :0;
	long long b:6;
	int c:8;
	char d;
	long long e:6;
	int f:8;
	char g;
};

#pragma pack(1)

// Verify bitfield grouping and alignment without zero-length bitfields

struct B1p1 {
	char a;
	unsigned short b:6;
	int c:8;
	short d:4;
}; 

struct B2p1 {
	char a;
	unsigned short b:6;
	int c:8;
	int d:4;
}; 

struct B3p1 {
	char a;
	unsigned short b:6;
	int c:8;
	char d; // gcc groups with int bit-field
}; 



// Verify bitfield grouping and alignment with zero-length bitfields

struct Z1p1 {
	char a;
	int :0; // MSVC ignores field
	unsigned short b:6;
	int c:8;
	short d:4;
}; 

struct Z2p1 {
	char a;
	unsigned short b:6;
	int c:8;
	int :0;
	short d:4;
}; 

struct Z3p1 {
	char a;
	unsigned short b:6;
	int c:8;
	int d:4;
	long long :0; // trailing :0 (ignore when packing ?) - case needs more testing
}; 

struct Z4p1 {
	char a;
	unsigned short b:6;
	int c:8;
	long long :0; // forced alignment of non-bitfield
	char d;
}; 


#pragma pack()

// packed structure contained within default aligned structure 
struct Z3p1T {
	char a;
	struct Z3p1 z3p1;
};

#pragma pack(2)


// Verify bitfield grouping and alignment without zero-length bitfields

struct B1p2 {
	char a;
	unsigned short b:6;
	int c:8;
	short d:4;
}; 

struct B2p2 {
	char a;
	unsigned short b:6;
	int c:8;
	int d:4;
}; 

struct B3p2 {
	char a;
	unsigned short b:6;
	int c:8;
	char d; // gcc groups with int bit-field
}; 

struct B4p2 {
	char a;
	unsigned short b:6;
	int c:8;
	long long d;
	int e:4;
}; 



// Verify bitfield grouping and alignment with zero-length bitfields

struct Z1p2 {
	char a;
	int :0; // MSVC ignores field
	unsigned short b:6;
	int c:8;
	short d:4; // NOTE: gcc appears ignore short alignment constraint due to int :0 ???
}; 

struct Z1p2x {
	char a;
	int :0; // MSVC ignores field
	unsigned short b:6;
	int c:8;
	short d:4; // NOTE: gcc appears ignore short alignment constraint due to int :0 ???
	short d1:4;
	short d2:4;
	short d3:4;
	short d4:4;
	short d5:4;
	short d6:4;
	short d7:4;
	
	short :0;
	unsigned short _b:6;
	int _c:8;
	short _d:4; // NOTE: gcc appears ignore short alignment constraint due to int :0 ???
	short _d1:4;
	short _d2:4;
	short _d3:4;
	short _d4:4;
	short _d5:4;
	short _d6:4;
	short _d7:4;
	
};

struct Z2p2 {
	char a;
	unsigned short b:6;
	int c:8;
	int :0;
	short d:4;
}; 

struct Z3p2 {
	char a;
	unsigned short b:6;
	int c:8;
	int d:4;
	long long :0; // trailing :0 (ignore when packing ?) - case needs more testing
}; 

struct Z4p2 {
	char a;
	unsigned short b:6;
	int c:8;
	long long :0; // forced alignment of non-bitfield
	char d;
}; 

struct Z5p2 {
	char a;
	unsigned short b:12;
	int c:8;
	long long :0; // forced alignment of non-bitfield
	char d;
};

struct x1p2 {
	char a;
};

struct x2p2 {
	char a;
	int b:27;
};

struct x3p2 {
	char a;
	short :0;
	int b:27;
};

struct x4p2 {
	char a;
	int b:27;
	long long :0;
};


#pragma pack()

#pragma pack(4)

struct Z5p4 {
	char a;
	unsigned short b:12;
	int c:8;
	long long :0; // forced alignment of non-bitfield
	char d;
};

struct x1p4 {
	char a;
};

struct x2p4 {
	char a;
	int b:27;
};

struct x3p4 {
	char a;
	short :0;
	int b:27;
};

struct x4p4 {
	char a;
	int b:27;
	long long :0;
};

#pragma pack()


// Structures within structures

struct S1 {
	struct B1 b1;
	struct B2 b2;
	struct Z1 z1;
	struct Z2 z2;
	struct Z3 z3;
};


#pragma pack(1)

struct S1p1 {
	struct B1 b1;
	struct B2 b2;
	struct Z1 z1;
	struct Z2 z2;
	struct Z3 z3;
};

struct S2p1 {
	struct B1p1 b1p1;
	struct B2p1 b2p1;
	struct Z1p1 z1p1;
	struct Z2p1 z2p1;
	struct Z3p1 z3p1;
};

#pragma pack()


#pragma pack(2)

struct S1p2 {
	struct B1 b1;
	struct B2 b2;
	struct Z1 z1;
	struct Z2 z2;
	struct Z3 z3;
};

struct S2p2 {
	struct B1p2 b1p2;
	struct B2p2 b2p2;
	struct Z1p2 z1p2;
	struct Z2p2 z2p2;
	struct Z3p2 z3p2;
};

#pragma pack()

enum myEnum { ONE, TWO, THREE };

typedef enum myEnum enumTypedef; 

typedef int intTypedef;

typedef char charTypedef;

typedef short shortTypedef;

struct T1 {
	charTypedef a;
	enum myEnum b:3;
	enumTypedef c:3;
	charTypedef d:7;
};

struct T2 {
	charTypedef a;
	intTypedef b:17;
	enumTypedef c:3;
	charTypedef d:3;
};

// Unions

union U1 {
	int a:4;
	int b:2;
};

union U1z {
	int a:4;
	long long :0;
	int b:2;
};

#pragma pack(1)

union U1p1 {
	int a:4;
	int b:2;
};

union U1p1z {
	int a:4;
	long long :0;
	int b:2;
};

struct SUp1 {
	char a;
	union U1p1z u;
};

#pragma pack(2)

union U1p2 {
	int a:4;
	int b:2;
};

#pragma pack()

