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
#include "stdio.h"
#include "complex.h"

typedef struct _mystruct {
    int f1;
    long f2;
    short f3:4;
    short f4:4;
    short f5:4;
    short f6:4;
} mystruct, *mystruct_p, mystruct_arr[5];

typedef union _myunion {
    long as_long;
    float as_float;
} myunion, *myunion_p, myunion_arr[6];

typedef enum _myenum {
    FIRST = 0,
    SECOND,
} myenum, *myenum_p, myenum_arr[7];

typedef void (*myfunc_p)(int arg0, long arg1);
typedef void (*myvargfunc_p)(int arg0, long arg1, ...);

typedef myundef;

int int_var;
void* void_p_var;

__attribute__((section ("complex")))
float complex complex_var = 1 + 2*I;
__attribute__((section ("doublex")))
double complex double_complex_var = 3 + 4*I;
/*__attribute__((section ("ldoublex")))
long double complex long_double_complex_var = 5 + 6*I;*/

typedef struct _mycomplex {
    float real;
    float imag;
} mycomplex, *mycomplex_p;

typedef struct _mydoublex {
    double real;
    double imag;
} mydoublex, *mydoublex_p;

typedef struct _myldoublex {
    long double real;
    long double imag;
} myldoublex, *myldoublex_p;

typedef struct _mylist {
	struct _mylist* next;
	void* val;
} mylist, *mylist_p;

mystruct mystruct_var;
struct _mystruct struct_mystruct_var;
mystruct_p mystruct_p_var;
mystruct_arr mystruct_arr_var;

myunion myunion_var;
myenum myenum_var;
myfunc_p myfunc_p_var;
myvargfunc_p myvargfunc_p_var;
myundef myundef_var;
mylist_p mylist_p_var;

int main(int argc, char** argv) {
    printf("complex: %d\n", sizeof(complex_var));
    printf("double complex: %d\n", sizeof(double_complex_var));
    
    register mycomplex_p cparts = &complex_var;
    printf("single real: %f\n", cparts->real);
    printf("single imag: %f\n", cparts->imag);
    
    mydoublex_p dparts = &double_complex_var;
    printf("double real: %g\n", dparts->real);
    printf("double imag: %g\n", dparts->imag);
    
    /*myldoublex_p ldparts = &long_double_complex_var;
    printf("long double real: %lg\n", ldparts->real);
    printf("long double imag: %lg\n", ldparts->imag);*/
}

/*
Wrote:
1d000000000000002e0b00000000000000000000000407000000000000005f6d79656e756d
1d000000000000002e0f00000000000000000000000407000000000000005f6d79656e756d
Read: 49000000000000002f0b0000000407000000000000005f6d79656e756d07020000000000000005000000000000004649525354000000000000000006000000000000005345434f4e440100000000000000

Wrote: 1d000000000000002e0f00000000000000000000000407000000000000005f6d79656e756d
Read: 49000000000000002f0f0000000407000000000000005f6d79656e756d07020000000000000005000000000000004649525354000000000000000006000000000000005345434f4e440100000000000000

*/
