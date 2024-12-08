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
#include<stdlib.h>

//compile with fomit-frame-pointer
//how to turn off inferred variable references

long sum(void);
void diff(void);

int main(int argc, char **argv){    
    asm(".intel_syntax noprefix");
    register long a asm ("r14"); 
    register long b asm ("r15");  
    register long c asm ("rbx");
    asm(".att_syntax prefix");

    a = strtol(argv[1], NULL, 10);
    b = strtol(argv[2], NULL, 10);
    long s = sum();
    printf("sum: %ld\n", s);
    asm(".intel_syntax noprefix");
    asm("push r15");
    asm("push r14"); 
    asm(".att_syntax prefix");
    diff();
    printf("diff: %ld\n",c);
   
    return 0;
}

long sum(void){
    asm(".intel_syntax noprefix");
    asm("mov rax, r14");
    asm("add rax, r15");
}

void diff(void){
    asm(".intel_syntax noprefix");
    asm("mov rbx, [rsp+8]");
    asm("sub rbx, [rsp+0x10]");
    asm("ret 16");
}

    






