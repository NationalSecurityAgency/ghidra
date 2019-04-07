/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

#define A 'a'
#define FIVE 5
#define PI 3.14159

int total = 3;
static float average = PI;

double mypow(double x, double y) {
    return x*y;
}

int bob(int a, float b, char c) {
    a++;
    b+=a;
    char string[200];
    sprintf(string, "a=%d, b=%f, c=%c\n", a, b, c);
    printf(string);
    total++;
    average /= total;
    fprintf(stderr, "total=%d average=%f\n", total, average);
}

int hello() {
    printf("Hello World!\n");
    bob(42, PI, A);
    return FIVE;
}

float goodbye() {
    printf("Goodbye World!\n");
    bob(42, PI, A);
    return FIVE;
}

int main(int argc, char ** argv) {
    int i = 0;
    int looper = 0;
    hello();
    for (; i < 5; ++i) {
        printf("\ti = %d\n", i);
    }
    goodbye();
    bob(42, 2.18, 'x');
    printf("mypow: %f\n", mypow(2,3));
    while (1) {
        printf("looper=%d\n", ++looper);
        sleep(5);
    }
}
