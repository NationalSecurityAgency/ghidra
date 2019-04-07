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
// This is the "entry" part for the entire decompiler/sleigh library
// You should be able to include this header to get all functionality
// and we put a startup and shutdown routine here

#ifndef __LIBDECOMP__
#define __LIBDECOMP__

#include "architecture.hh"
#include "sleigh_arch.hh"
#include "ifacedecomp.hh"

// Initialize all decompiler capabilities and register any sleigh specifications
// If you have an entire ghidra distribution, you can specify its root with the -sleighhome- input,
// otherwise you can provide a list of directories that contain '.lspec' files.
extern void startDecompilerLibrary(const char *sleighhome);
extern void startDecompilerLibrary(const vector<string> &extrapaths);
extern void startDecompilerLibrary(const char *sleighhome,const vector<string> &extrapaths);

extern void shutdownDecompilerLibrary(void);

#endif
