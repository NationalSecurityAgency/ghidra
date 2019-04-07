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
#ifndef __PDB__SYMBOL__H__
#define __PDB__SYMBOL__H__

#include <stdio.h>
#include "dia2.h"
#include "diacreate.h"
#include "cvconst.h"

BSTR          getName(IDiaSymbol * pSymbol);
BSTR          getUndecoratedName(IDiaSymbol * pSymbol);
DWORD         getRVA(IDiaSymbol * pSymbol);
ULONGLONG     getLength(IDiaSymbol * pSymbol);
DWORD         getTag(IDiaSymbol * pSymbol);
BSTR          getTagAsString(IDiaSymbol * pSymbol);
DWORD         getKind(IDiaSymbol * pSymbol);
BSTR          getKindAsString(IDiaSymbol * pSymbol);
DWORD         getUdtKind(IDiaSymbol * pSymbol);
LONG          getOffset(IDiaSymbol * pSymbol);
DWORD         getIndex(IDiaSymbol * pSymbol);
wchar_t *     getValue(IDiaSymbol * pSymbol);
DWORD         getBaseType(IDiaSymbol * pSymbol);
BSTR          getBaseTypeAsString(IDiaSymbol * pSymbol);
IDiaSymbol *  getType(IDiaSymbol * pSymbol);
BSTR          getTypeAsString(IDiaSymbol * pSymbol);

bool          isScopeSym( DWORD tag );


#endif
