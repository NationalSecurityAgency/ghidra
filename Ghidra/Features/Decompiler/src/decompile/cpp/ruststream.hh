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

#ifndef __RUSTSTREAM__
#define __RUSTSTREAM__

#include <istream>
#include "rust/cxx.h"

// Rust reader adapters adapts to internal stream
class StreamReader {
private:
    std::istream &stream;

public:
    StreamReader(std::istream &stream): stream(stream) {}

    std::size_t read(rust::Slice<uint8_t> buf);
};

#endif