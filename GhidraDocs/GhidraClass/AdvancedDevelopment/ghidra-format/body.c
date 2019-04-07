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

static unsigned int alpha = 0xfeedbabe;

int foo( int bar )
{
    return bar * bar / bar + bar - bar % bar;
}

int main ( int argc, const char ** argv )
{
    alpha *= 8;

    printf( "Hello Ghidra!\n" );
    
    int foobar = foo( 0x12345678 );

    printf( "foobar = %x \n", foobar * alpha );
    return 0;
}
