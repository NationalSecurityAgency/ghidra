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

BSTR findMangledName(IDiaSymbol * pFunction) {
	DWORD rva = getRVA(pFunction);
	IDiaSymbol * pSymbol = NULL;
	HRESULT hr = pSession->findSymbolByRVA(rva, SymTagPublicSymbol, &pSymbol);
	if (hr == S_OK) {
		DWORD tag = getTag(pSymbol);
		if (tag == SymTagPublicSymbol) {//do not delete
			DWORD address = getRVA(pSymbol);
			if (address == rva) {
				return getName(pSymbol);
			}
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
	IDiaEnumSymbols * pEnum;
	if ( FAILED( pGlobal->findChildren( SymTagNull, name, nsCaseSensitive, &pEnum ) ) ) {
		fatal( "Namespace findChildren failed" );
	}
	long cnt = 0;
	if ( pEnum != NULL && SUCCEEDED( pEnum->get_Count(&cnt) ) && cnt > 0 ) {   // Found a name.
		printNameFromScope( name, pGlobal, pEnum );
	}
	delete [] buf;
}

void findNameInEnum( wchar_t* name, IDiaSymbol* penumeration )
{
	IDiaEnumSymbols * pEnum;
	if ( FAILED( penumeration->findChildren( SymTagData, name, nsRegularExpression, &pEnum ) ) ) {
		fatal( "Enumeration findChildren failed" );
	}
	long cnt = 0;
	if ( pEnum != NULL && SUCCEEDED( pEnum->get_Count(&cnt) ) && cnt > 0 ) {   // Found a name.
		printNameFromScope( name, penumeration, pEnum );
	}
}

void findNameInClass( wchar_t* name, IDiaSymbol* pclass )
{
	IDiaEnumSymbols * pEnum;
	if ( FAILED( pclass->findChildren( SymTagNull, name, nsCaseSensitive, &pEnum ) ) ) {
		fatal( "Class findChildren failed" );
	}
	long cnt = 0;
	if ( pEnum != NULL && SUCCEEDED( pEnum->get_Count(&cnt) ) && cnt > 0 ) {   // Found a name.
		printNameFromScope( name, pclass, pEnum );
	}
	pEnum = 0;
	// Check out the enumerations.
	IDiaSymbol * pSym;
	if ( FAILED( pclass->findChildren( SymTagEnum, NULL, nsNone, &pEnum ) ) ) {
		fatal( "Class findChildren for enums failed" );
	}
	if ( pEnum != NULL && SUCCEEDED( pEnum->get_Count(&cnt) ) && cnt > 0 ) {   // Found an enum.
		DWORD celt;
		while ( SUCCEEDED( pEnum->Next( 1, &pSym, &celt ) ) && celt == 1 ) {
			findNameInEnum( name, pSym );
			pSym = 0;
		}
	}
	pEnum = 0;
	// Check out the base classes.
	if ( FAILED( pclass->findChildren( SymTagBaseClass, NULL, nsNone, &pEnum ) ) ) {
		fatal( "Class findChildren for base classes failed" );
	}
	if ( pEnum != NULL && SUCCEEDED( pEnum->get_Count(&cnt) ) && cnt > 0 ) {   // Found a base class.
		DWORD celt;
		while ( SUCCEEDED( pEnum->Next( 1, &pSym, &celt ) ) && celt == 1 ) {
			IDiaSymbol * pClass;
			if (  pSym->get_type( &pClass ) == S_OK ) {
				fatal( "Getting class for a base type failed" );
			}
			if ( pClass ) {
				findNameInClass( name, pClass );
			}
			pSym = 0;
		}
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
	IDiaSymbol * pSym;
	IDiaSymbol * pParent;
	IDiaSymbol * pscope;
	for ( pscope = pScope; pscope != NULL; ) {
		IDiaEnumSymbols * pEnum;
		// Local data search
		if ( FAILED( pscope->findChildren( SymTagNull, name, nsCaseSensitive, &pEnum ) ) ) {
			fatal( "Local scope findChildren failed" );
		}
		if ( pEnum != NULL && SUCCEEDED( pEnum->get_Count(&cnt) ) && cnt > 0 ) {   // Found a name.
			printNameFromScope( name, pscope, pEnum );
		}
		pEnum = 0;
		// Look into any namespaces.
		if ( FAILED( pscope->findChildren( SymTagUsingNamespace, NULL, nsNone, &pEnum ) ) ) {
			fatal( "Namespace findChildren failed" );
		}
		if ( pEnum != NULL && SUCCEEDED( pEnum->get_Count(&cnt) ) && cnt > 0 ) {   // Found a namespace.
			while ( SUCCEEDED( pEnum->Next( 1, &pSym, &celt ) ) && celt == 1 ) {
				findNameInNamespace( name, pSym );
				pSym = 0;
			}
		}
		pEnum = 0;
		// Check if this is a member function.
		DWORD tag = SymTagNull;
		if ( SUCCEEDED( pscope->get_symTag( &tag ) ) && tag == SymTagFunction && SUCCEEDED( pscope->get_classParent( &pParent ) ) && pParent != NULL ) {
			findNameInClass( name, pParent );
		}
		pParent = NULL;
		// Move to lexical parent.
		if ( SUCCEEDED( pscope->get_lexicalParent( &pParent ) ) && pParent != NULL ) {
			pscope = pParent;
		} 
		else {
			pscope = NULL;
		}
		pParent = NULL;
	};
}
