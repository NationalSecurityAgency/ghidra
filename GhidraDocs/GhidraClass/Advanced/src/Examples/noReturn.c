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
#include<stdio.h>

//compile with -shared -fPIC, no optimizations

void __attribute__((noreturn)) loopForever(int);
void printInput(unsigned long, unsigned long);
void printInputThenLoop(unsigned long, unsigned long);

void __attribute__((noreturn)) loopForever(int x)  {
    for(;;){
        printf("x: %d\n",x);
    }
}

void printInputThenLoop1(unsigned long a, unsigned long b){
    printf("\na: %lu, b: %lu\n",a,b);
    loopForever(1);
}

asm (".byte 0xff");
asm (".byte 0xff");

void printInput(unsigned long a, unsigned long b){
    printf("\na: %lu, b%lu\n\n",a,b);
    return;
}

void printInputThenLoop2(unsigned long a, unsigned long b){
    printf("\na: %lu, b: %lu\n", a,b);
    loopForever(2);
}

asm (".byte 0xe8");

unsigned long add(unsigned long a, unsigned long b){
    return a+b;
}
