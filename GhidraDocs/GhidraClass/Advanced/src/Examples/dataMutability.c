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

char * const readOnly = "This string can't be modified, so the decompiler will show it.";
char *writeable = "This string might change, so the decompiler won't show it.";

volatile int status;

int counter;

int main(int argc, char **argv){ 
    printf("%s\n",readOnly);
    printf("%s\n",writeable);
    status = 0;
    while (status == 0){
        counter++;
    }
    printf("\nEncountered non-zero value for status. Counter = %d\n", counter);
    return 0;
}


