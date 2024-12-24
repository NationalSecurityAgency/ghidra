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
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

pthread_t thread;

void* work(void* param) {
    printf("I'm %d, PID: %d\n", (int)param, getpid());
    if (param == NULL) {
        return (void*)1;
    } else {
        //sleep(10);
        return (void*)2;
    }
}

int main() {
    pthread_create(&thread, NULL, work, (void*)1);
    sleep(1); // Not ideal, but some assurance that we break with two threads
    return (int)work(NULL);
}
