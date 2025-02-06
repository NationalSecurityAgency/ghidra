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
#ifndef INCLUDE1
#define INCLUDE1
#pragma pack(push,1)

#elif !defined(INCLUDE2)
#define INCLUDE2
#pragma pack(push, 2)

#elif !defined(INCLUDE3)
#define INCLUDE3
#pragma pack(push, 4)

#elif !defined(INCLUDE4)
#define INCLUDE4
#pragma pack(push, 8)

#else
#define INCLUDE5  // never gets to this
#endif
