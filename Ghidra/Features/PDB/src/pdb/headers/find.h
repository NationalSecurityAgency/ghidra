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
#ifndef __PDB__FIND__H__
#define __PDB__FIND__H__

#include <stdio.h>
#include <assert.h>
#include "dia2.h"
#include "diacreate.h"
#include "cvconst.h"
#include "pdb.h"
#include "print.h"
#include "symbol.h"
#include <string>

//
//The name of SymTagFunction symbol are demangled.
//This method locates the mangled
//function name, which is stored in a SymTagPublicSymbol symbol.
//
std::wstring findMangledName(PDBApiContext& ctx, IDiaSymbol& pFunction);
void findNameInNamespace(PDBApiContext& ctx, const std::wstring& name, IDiaSymbol& pnamespace );
void findNameInEnum( const std::wstring& name, IDiaSymbol& penumeration );
void findNameInClass( const std::wstring& name, IDiaSymbol& pclass );
void findCppNameInScope( const std::wstring& name, IDiaSymbol& pScope );

#endif
