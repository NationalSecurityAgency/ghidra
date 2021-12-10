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
// TEMPORARY / TESTING - Zero-length Array Components
//  - how should trailing zero-length arrays be handled/defined within structure since they may have an
//    offset equal to the length of the structure (current flex array only allows for 1).  The last component
//    may not remain the last components as components are added.  In addition, multiple trailing flex-arrays 
//    may exist.
 
struct zeroArrayStruct1 {
		int  a;
		char a1[2];
        char x[0];
        int  y[0];
        int  b;
};

struct zeroArrayStruct2 {
		int  a;
		char a1[2];
        char x[0];
        int  y[0];
};

struct zeroArrayStruct3 {
		int  a;
		zeroArrayStruct2 s;
};

union zeroArrayUnion1 {
		int  a;
		char a1[2];
        char x[0];
        int  y[0];
        int  b;
};

union zeroArrayUnion2 {
		int  a;
		char a1[2];
        char x[0];
        int  y[0];
};

union zeroArrayUnion3 {
		int  a;
		zeroArrayStruct2 s;
};
