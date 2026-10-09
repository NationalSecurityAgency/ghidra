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
// Rebuild the ELF fixtures from this directory with LLVM 23.1.2:
// clang++ --target=x86_64-unknown-linux-gnu -g -gdwarf-4 -fdebug-types-section -c sample.cpp -o type_sample.o
// clang++ --target=x86_64-unknown-linux-gnu -g -gdwarf-4 -gsplit-dwarf -fdebug-types-section -c sample.cpp -o split_v4.o
// clang++ --target=x86_64-unknown-linux-gnu -g -gdwarf-5 -gsplit-dwarf -fdebug-types-section -c sample.cpp -o sample.o
// llvm-objcopy --compress-debug-sections=zlib sample.dwo sample_compressed.dwo
// The split-dwarf commands also generate split_v4.dwo and sample.dwo.
struct Point { int x; int y; };
Point move(Point p) { return {p.x + 1, p.y + 1}; }
