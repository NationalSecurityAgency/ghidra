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
#ifndef __PDB__PRINT__H__
#define __PDB__PRINT__H__

#include <stdio.h>
#include <assert.h>
#include "dia2.h"
#include "diacreate.h"
#include "cvconst.h"
#include <string>

std::wstring printVariant( VARIANT & v );
std::wstring printType( IDiaSymbol* pType, const std::wstring& prefix );

void printBound( IDiaSymbol& pBound );
void printScopeName( IDiaSymbol& pscope );
void printNameFromScope( IDiaSymbol& pscope, IDiaEnumSymbols& pEnum );

#endif
