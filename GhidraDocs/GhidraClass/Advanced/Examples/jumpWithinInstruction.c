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

void printMessage(void);

int main(int argc, char **argv){
    asm(".intel_syntax noprefix");
    asm(".byte 0xeb, 0xff, 0xc0, 0x67, 0x48");
    asm(".att_syntax prefix");
    printMessage();
    return EXIT_SUCCESS;
}

void printMessage(void){
    printf("\nIn printMessage function.\n\n");
    return;
}
