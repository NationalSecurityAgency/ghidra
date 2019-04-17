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

long switchFunc(long);

int main(int argc, char **argv){
    long x = strtol(argv[1],NULL,10);
    return (int) switchFunc(x);
}

long switchFunc(long x){
    long retVal = 0;
    switch(x){
        case 0:
            retVal = 0;
            printf("\nReturning %ld\n\n", retVal);
            break;
        case 1:
            retVal = 1;
            printf("\nReturning %ld\n\n", retVal);
            break;
        case 2:
            retVal = 22;
            printf("\nReturning %ld\n\n", retVal);
            break;
        case 3:
            retVal = 333;
            printf("\nReturning %ld\n\n", retVal);
            break;
        case 4:
            retVal = 4444;
            printf("\nReturning %ld\n\n", retVal);
            break;            
        case 5:
            retVal = 55555;
            printf("\nReturning %ld\n\n", retVal);
            break;
        case 6:
            retVal = 666666;
            printf("\nReturning %ld\n\n", retVal);
            break;
        case 7:
            retVal = 7777777;
            printf("\nReturning %ld\n\n", retVal);
            break;
        case 8:
            retVal = 88888888;
            printf("\nReturning %ld\n\n", retVal);
            break;
        case 9:
            retVal = 999999999;
            printf("\nReturning %ld\n\n", retVal);
            break;
        default:
            retVal = -1;
            printf("\nReturning %ld\n\n", retVal);
            break;
    }
    return retVal;
}
