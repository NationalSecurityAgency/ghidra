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

#include "ruststream.hh"
#include <memory>
#include <vector>

std::size_t StreamReader::read(rust::Slice<uint8_t> buf) {
    uint size = 0;
    char c;
    while (size < buf.size() && stream.get(c)) {
        buf[size] = c;
        size ++;
    }

    return size;
}