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
#include "find.h"
#include <atlcomcli.h>
#include <comutil.h>

std::wstring findMangledName(PDBApiContext& ctx, IDiaSymbol& function) {
	const DWORD rva = getRVA(function);
	CComPtr<IDiaSymbol> pSymbol;
	if (ctx.Session().findSymbolByRVA(rva, SymTagPublicSymbol, &pSymbol) == S_OK) {
		const DWORD tag = getTag(*pSymbol);
		if (tag == SymTagPublicSymbol) {//do not delete
			const DWORD address = getRVA(*pSymbol);
			if (address == rva) {
				return getName(*pSymbol);
			}
		}
	}
	return getName(function);
}

void findNameInNamespace(PDBApiContext& ctx, const std::wstring& name, IDiaSymbol& myNamespace )
{
	bstr_t bstrNamespace;
	if (FAILED(myNamespace.get_name(bstrNamespace.GetAddress()))) {
		fatal("Namespace get_name failed");
	}

	const std::wstring strNamespace(bstrNamespace.GetBSTR(), bstrNamespace.length());
	const std::wstring fullName = strNamespace + L"::" + name;

	CComPtr<IDiaEnumSymbols> pEnum;
	if ( FAILED(ctx.Global().findChildren( SymTagNull, fullName.c_str(), nsCaseSensitive, &pEnum ) ) ) {
		fatal( "Namespace findChildren failed" );
	}

	long cnt = 0;
	if ( pEnum != NULL && pEnum->get_Count(&cnt) == S_OK && cnt > 0 ) {   // Found a name.
		printNameFromScope(ctx.Global(), *pEnum );
	}
}

void findNameInEnum( const std::wstring& name, IDiaSymbol& enumeration )
{
	CComPtr<IDiaEnumSymbols> pEnum;
	if ( FAILED( enumeration.findChildren( SymTagData, name.c_str(), nsRegularExpression, &pEnum ) ) ) {
		fatal( "Enumeration findChildren failed" );
	}
	long cnt = 0;
	if ( pEnum != NULL && pEnum->get_Count(&cnt) == S_OK && cnt > 0 ) {   // Found a name.
		printNameFromScope( enumeration, *pEnum );
	}
}

// 20190716: TODO: Investigate... This function appears to be only called by
// itself and by findCppNameInScope, which currently appears to be unused.
void findNameInClass( const std::wstring& name, IDiaSymbol& myClass )
{
	{
		CComPtr<IDiaEnumSymbols> pEnum;
		if (FAILED(myClass.findChildren(SymTagNull, name.c_str(), nsCaseSensitive, &pEnum))) {
			fatal("Class findChildren failed");
		}
		long cnt = 0;
		if (pEnum != NULL && pEnum->get_Count(&cnt) == S_OK && cnt > 0) {   // Found a name.
			printNameFromScope(myClass, *pEnum);
		}
	}

	{
		// Check out the enumerations.
		CComPtr<IDiaEnumSymbols> pEnum;
		CComPtr<IDiaSymbol> pSym;
		if (FAILED(myClass.findChildren(SymTagEnum, NULL, nsNone, &pEnum))) {
			fatal("Class findChildren for enums failed");
		}

		long cnt = 0;
		if (pEnum != NULL && pEnum->get_Count(&cnt) == S_OK && cnt > 0) {   // Found an enum.
			DWORD celt;
			while (pEnum->Next(1, &pSym, &celt) == S_OK && celt == 1) {
				findNameInEnum(name, *pSym);
				pSym = 0;
			}
		}
	}

	{
		// Check out the base classes.
		CComPtr<IDiaEnumSymbols> pEnum;

		if (FAILED(myClass.findChildren(SymTagBaseClass, NULL, nsNone, &pEnum))) {
			fatal("Class findChildren for base classes failed");
		}

		long cnt = 0;
		if (pEnum != NULL && pEnum->get_Count(&cnt) == S_OK && cnt > 0) {   // Found a base class.
			DWORD celt;
			CComPtr<IDiaSymbol> pSym;
			while (pEnum->Next(1, &pSym, &celt) == S_OK && celt == 1) {
				CComPtr<IDiaSymbol> pClass;
				if (pSym->get_type(&pClass) != S_OK ) {
					fatal("Getting class for a base type failed");
				}
				if (pClass) {
					findNameInClass(name, *pClass);
				}
				pSym = 0;
			}
		}
	}
}

// 20190716: TODO: Investigate... This code appears to be unused.  Also see
// note on function findNameInClass.
void findCppNameInScope(PDBApiContext& ctx, const std::wstring& name, IDiaSymbol& scope )
{
	// while ( scope ) {
	// Scan the scope for a symbol.
	// If any namespaces, then scan for name in namespace.
	// If scope is a member function then 
	//   scan class parent for member with name.
	// scope = scope.parent;
	// }

	printf( "Finding name \"%S\" in ", name.c_str() );
	printScopeName( scope );
	printf( "\n" );

	DWORD celt;
	long cnt = 0;
	CComPtr<IDiaSymbol> pSym;
	CComPtr<IDiaSymbol> pParent;
	CComPtr<IDiaSymbol> pscope;
	for ( pscope = &scope; pscope != NULL; ) {
		CComPtr<IDiaEnumSymbols> pEnum;
		// Local data search
		if ( FAILED( pscope->findChildren( SymTagNull, name.c_str(), nsCaseSensitive, &pEnum ) ) ) {
			fatal( "Local scope findChildren failed" );
		}
		if ( pEnum != NULL && pEnum->get_Count(&cnt) == S_OK && cnt > 0 ) {   // Found a name.
			printNameFromScope( *pscope, *pEnum );
		}
		pEnum = 0;
		// Look into any namespaces.
		if ( FAILED( pscope->findChildren( SymTagUsingNamespace, NULL, nsNone, &pEnum ) ) ) {
			fatal( "Namespace findChildren failed" );
		}
		if ( pEnum != NULL && pEnum->get_Count(&cnt) == S_OK && cnt > 0 ) {   // Found a namespace.
			while ( pEnum->Next( 1, &pSym, &celt ) == S_OK && celt == 1 ) {
				findNameInNamespace( ctx, name, *pSym );
				pSym = 0;
			}
		}
		pEnum = 0;
		// Check if this is a member function.
		DWORD tag = SymTagNull;
		if ( pscope->get_symTag( &tag ) == S_OK && tag == SymTagFunction && pscope->get_classParent( &pParent ) == S_OK && pParent != NULL ) {
			findNameInClass( name, *pParent );
		}
		pParent = NULL;
		// Move to lexical parent.
		if ( pscope->get_lexicalParent( &pParent ) == S_OK && pParent != NULL ) {
			pscope = pParent;
		} 
		else {
			pscope = NULL;
		}
		pParent = NULL;
	};
}
