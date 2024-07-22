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

long func1(long, long, long);
long func2(long, long, long, long);
long sumOfSquares(long,long);

int main(int argc, char **argv){
     if (argc != 5){
         printf("\nUsage: %s a b c d\n\n",argv[0]);
         return EXIT_SUCCESS;
     }
     long a = strtol(argv[1],NULL,10);
     long b = strtol(argv[2],NULL,10);
     long c = strtol(argv[3],NULL,10);
     long d = strtol(argv[4],NULL,10);
     return (int) (func1(a,b,c) + func2(a,b,c,d));
}

long func1(long a, long b, long c){
    long x = c*(a+b);
    long y = c*(a-b);
    return sumOfSquares(x,y);
}


long func2(long a, long b, long c, long d){
    long x = a*c;
    long y = b*d;
    return sumOfSquares(x,y);
}

long sumOfSquares(long a, long b){
    return a*a + b*b;
}
