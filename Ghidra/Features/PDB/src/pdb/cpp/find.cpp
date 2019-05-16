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
#include "find.h"

#define ITF_RELEASE(X) { if (NULL != X) { X->Release(); X = NULL; } }

BSTR findMangledName(IDiaSymbol * pFunction) {
	DWORD rva = getRVA(pFunction);
	IDiaSymbol * pSymbol = NULL;
	HRESULT hr = pSession->findSymbolByRVA(rva, SymTagPublicSymbol, &pSymbol);
	if (hr == S_OK) {
		BSTR result = NULL;
		DWORD tag = getTag(pSymbol);
		if (tag == SymTagPublicSymbol) {//do not delete
			DWORD address = getRVA(pSymbol);
			if (address == rva) {
				result = getName(pSymbol);
			}
		}
		ITF_RELEASE(pSymbol);
		if (NULL != result) {
			return result;
		}
	}
	return getName(pFunction);
}

void findNameInNamespace( wchar_t* name, IDiaSymbol* pnamespace )
{
	wchar_t * buf = NULL;
	BSTR szNamespace;
	pnamespace->get_name( &szNamespace );
	buf = new wchar_t[ wcslen( name ) + wcslen( szNamespace ) + 3];
	wsprintfW( buf, L"%s::%s", szNamespace, name );
	IDiaEnumSymbols * pEnum = NULL;
	if ( FAILED( pGlobal->findChildren( SymTagNull, name, nsCaseSensitive, &pEnum ) ) ) {
		fatal( "Namespace findChildren failed" );
	}
	long cnt = 0;
	if ( pEnum != NULL) {
		if (SUCCEEDED(pEnum->get_Count(&cnt)) && cnt > 0) {   // Found a name.
			printNameFromScope(name, pGlobal, pEnum);
		}
		ITF_RELEASE(pEnum);
	}
	delete [] buf;
}

void findNameInEnum( wchar_t* name, IDiaSymbol* penumeration )
{
	IDiaEnumSymbols * pEnum = NULL;
	if ( FAILED( penumeration->findChildren( SymTagData, name, nsRegularExpression, &pEnum ) ) ) {
		fatal( "Enumeration findChildren failed" );
	}
	long cnt = 0;
	if ( pEnum != NULL) {
		if (SUCCEEDED(pEnum->get_Count(&cnt)) && cnt > 0) {   // Found a name.
			printNameFromScope(name, penumeration, pEnum);
		}
		ITF_RELEASE(pEnum);
	}
}

void findNameInClass( wchar_t* name, IDiaSymbol* pclass )
{
	IDiaEnumSymbols * pEnum = NULL;
	if ( FAILED( pclass->findChildren( SymTagNull, name, nsCaseSensitive, &pEnum ) ) ) {
		fatal( "Class findChildren failed" );
	}
	long cnt = 0;
	if (pEnum != NULL) {
		if (SUCCEEDED(pEnum->get_Count(&cnt)) && cnt > 0) {   // Found a name.
			printNameFromScope(name, pclass, pEnum);
		}
		ITF_RELEASE(pEnum);
	}
	// Check out the enumerations.
	IDiaSymbol * pSym = NULL;
	if ( FAILED( pclass->findChildren( SymTagEnum, NULL, nsNone, &pEnum ) ) ) {
		fatal( "Class findChildren for enums failed" );
	}
	if ( pEnum != NULL) {
		if (SUCCEEDED(pEnum->get_Count(&cnt)) && cnt > 0) {   // Found an enum.
			DWORD celt;
			pSym = NULL;
			while (SUCCEEDED(pEnum->Next(1, &pSym, &celt)) && celt == 1) {
				findNameInEnum(name, pSym);
				ITF_RELEASE(pSym);
			}
			ITF_RELEASE(pSym);
		}
		// FIX 579 Don't release pEnum. We reuse it later.
	}
	// Check out the base classes.
	if ( FAILED( pclass->findChildren( SymTagBaseClass, NULL, nsNone, &pEnum ) ) ) {
		fatal( "Class findChildren for base classes failed" );
	}
	if ( pEnum != NULL) {
		if (SUCCEEDED(pEnum->get_Count(&cnt)) && cnt > 0) {   // Found a base class.
			DWORD celt;
			while (SUCCEEDED(pEnum->Next(1, &pSym, &celt)) && celt == 1) {
				IDiaSymbol* pClass;
				// FIX579 : Incidentally discovered this test logic was erroneous.
				// Changed the comparator from == to !=
				if (pSym->get_type(&pClass) != S_OK) {
					fatal("Getting class for a base type failed");
				}
				if (pClass) {
					findNameInClass(name, pClass);
					ITF_RELEASE(pClass);
				}
				ITF_RELEASE(pSym);
			}
		}
		ITF_RELEASE(pEnum);
	}
}

void findCppNameInScope( wchar_t* name, IDiaSymbol* pScope )
{
	// while ( scope ) {
	// Scan the scope for a symbol.
	// If any namespaces, then scan for name in namespace.
	// If scope is a member function then 
	//   scan class parent for member with name.
	// scope = scope.parent;
	// }

	wprintf( L"Finding name \"%ws\" in ", name );
	printScopeName( pScope );
	wprintf( L"\n" );

	DWORD celt;
	long cnt = 0;
	// FIX 579 : Renamed to avaoid confusion with function parameter.
	IDiaSymbol * pLocalScope = NULL;
	for ( pLocalScope = pScope; pLocalScope != NULL; ) {
		IDiaEnumSymbols * pEnum = NULL;
		// Local data search
		if ( FAILED( pLocalScope->findChildren( SymTagNull, name, nsCaseSensitive, &pEnum ) ) ) {
			fatal( "Local scope findChildren failed" );
		}
		if ( pEnum != NULL) {
			if (SUCCEEDED(pEnum->get_Count(&cnt)) && cnt > 0) {   // Found a name.
				printNameFromScope(name, pLocalScope, pEnum);
			}
			// FIX 579 Don't release pEnum. It's used later.
		}
		// Look into any namespaces.
		if ( FAILED( pLocalScope->findChildren( SymTagUsingNamespace, NULL, nsNone, &pEnum ) ) ) {
			fatal( "Namespace findChildren failed" );
		}
		if ( pEnum != NULL) {
			if (SUCCEEDED(pEnum->get_Count(&cnt)) && cnt > 0) {   // Found a namespace.
				// FIX579 : Declaration moved here for scope reduction.
				IDiaSymbol* pSym = NULL;
				while (SUCCEEDED(pEnum->Next(1, &pSym, &celt)) && celt == 1) {
					findNameInNamespace(name, pSym);
					ITF_RELEASE(pSym);
				}
			}
			// FIX 579 Won't be used later.
			ITF_RELEASE(pEnum);
		}
		// Check if this is a member function.
		DWORD tag = SymTagNull;
		if ( SUCCEEDED( pLocalScope->get_symTag( &tag ) ) && tag == SymTagFunction) {
			// FIX 579 : Declaration moved here for scope reduction.
			IDiaSymbol* pParent = NULL;
			if (SUCCEEDED(pLocalScope->get_classParent(&pParent))) {
				if (pParent != NULL) {
					findNameInClass(name, pParent);
					ITF_RELEASE(pParent);
				}
			}
		}
		// Move to lexical parent.
		IDiaSymbol* pNextScope = NULL;
		pLocalScope->get_lexicalParent(&pNextScope);
		ITF_RELEASE(pLocalScope);
		pLocalScope = pNextScope;
	};
	// FIX 579 : Should not be required. Safety.
	ITF_RELEASE(pLocalScope);
}
