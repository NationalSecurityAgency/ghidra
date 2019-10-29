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
#include "pdb.h"
#include "find.h"
#include "print.h"
#include "symbol.h"
#include <atlcomcli.h>
#include <comutil.h>
#include <vector>

// Returns a mixture of static strings and allocated strings.
// Abandon all hope of memory management, ye who enter here
std::wstring printVariant( VARIANT & v ) {
	
	// handle results that don't need a format buffer
	switch( v.vt ) {
		case VT_BOOL://Indicates a Boolean value. 
			return v.boolVal == 0 ? L"false" : L"true";
		case VT_BSTR://Indicates a BSTR string. 
			return v.bstrVal;
		case VT_EMPTY://Indicates that a value was not specified. 
			return L"empty";
		case VT_NULL://Indicates a a null reference (Nothing in Visual Basic) value, similar to a null value in SQL. 
			return L"null";
	}

	const int blen = 100;
	wchar_t variant[blen] = {};
	switch( v.vt ) {
		case VT_ARRAY://Indicates a SAFEARRAY pointer. 
			swprintf_s(variant, blen, L"%I64d", (ULONGLONG) v.parray);//TODO
			return variant;
		case VT_BYREF://Indicates that a value is a reference. 
			swprintf_s(variant, blen, L"%I64d", (ULONGLONG) v.cVal);//TODO
			return variant;
		case VT_CY://Indicates a currency value. 
			swprintf_s(variant, blen, L"%I64d", (ULONGLONG) v.cyVal.int64);
			return variant;
		case VT_DATE://Indicates a DATE value. 
			swprintf_s(variant, blen, L"%I64d", (ULONGLONG) v.date);
			return variant;
		case VT_DISPATCH://Indicates an IDispatch pointer. 
			swprintf_s(variant, blen, L"%I64d", (ULONGLONG) v.pdispVal);
			return variant;
		case VT_ERROR://Indicates an SCODE. 
			swprintf_s(variant, blen, L"0x%x", v.scode);
			return variant;
		case VT_I1://CHAR
			swprintf_s(variant, blen, L"%d", v.cVal);
			return variant;
		case VT_I2://SHORT
			swprintf_s(variant, blen, L"%d", v.iVal);
			return variant;
		case VT_I4://LONG
			swprintf_s(variant, blen, L"%d", v.lVal );
			return variant;
		case VT_I8: //LONGLONG
			swprintf_s(variant, blen, L"%I64d", v.llVal );
			return variant;
		case VT_INT://INT
			swprintf_s(variant, blen, L"%d", v.intVal);
			return variant;
		case VT_R4://Indicates a float value. 
			swprintf_s(variant, blen, L"%f", v.fltVal);
			return variant;
		case VT_R8://Indicates a double value. 
			swprintf_s(variant, blen, L"%f", v.dblVal);
			return variant;
		case VT_UI1://BYTE
			swprintf_s(variant, blen, L"%d", v.bVal);
			return variant;
		case VT_UI2://USHORT
			swprintf_s(variant, blen, L"%d", v.uiVal);
			return variant;
		case VT_UI4://ULONG
			swprintf_s(variant, blen, L"%d", v.ulVal);
			return variant;
		case VT_UI8://ULONGLONG
			swprintf(variant, blen, L"%I64d", v.ullVal);
			return variant;
		case VT_UINT://UINT
			swprintf_s(variant, blen, L"%d", v.uintVal);
			return variant;
		case VT_UNKNOWN://Indicates an IUnknown pointer. 
			swprintf_s(variant, blen, L"%I64d", (ULONGLONG) v.punkVal);
			return variant;
		case VT_VARIANT://Indicates a VARIANT far pointer. 
			swprintf_s(variant, blen, L"%I64d", (ULONGLONG) v.pvarVal);
			return variant;

		default:
			return L"unknown";
	}
}

void printBound( IDiaSymbol& bound ) {

	DWORD tag = 0;
	DWORD kind = 0;
	bound.get_symTag( &tag );
	bound.get_locationType( &kind );
	bstr_t name;
	if ( tag == SymTagData && kind == LocIsConstant ) {
		//TODO
		//CComVariant v;
		//pBound->get_value( &v );
		//printVariant( v );
	} 
	else if ( bound.get_name( name.GetAddress()) == S_OK ) {
		printf( "%ws", name.GetBSTR() );
	}
}

std::wstring printType( IDiaSymbol * pType, const std::wstring& suffix ) {
	if (pType == NULL) {
		return L"";
	}
	std::wstring name = getName(*pType);
	DWORD tag = getTag(*pType);

	if ( tag == SymTagPointerType ) {
		CComPtr<IDiaSymbol> pBaseType;
		if ( pType->get_type( &pBaseType ) == S_OK ) {
			return printType(pBaseType, suffix + L" *");
		}
		else {
			return L"";
		}
	} 

	if ( tag == SymTagBaseType ) {
		return getBaseTypeAsString( *pType ) + suffix;
	}

	if ( tag == SymTagArrayType ) {
		CComPtr<IDiaSymbol> pBaseType = getType( *pType );
		if ( pBaseType == NULL ) {
			return L"";
		}
		ULONGLONG lenArray = getLength( *pType );
		ULONGLONG lenElem  = getLength( *pBaseType );
		if (lenElem == 0) {//prevent divide by zero...
			lenElem = lenArray;
		}
		const size_t strLen = suffix.length() + 64 + 3;	// length of suffix + wag_for_numeric_value + "[]\0" 
		std::vector<wchar_t> str(strLen);
		swprintf_s(str.data(), strLen, L"%s[%I64d]", suffix.c_str(), lenArray / lenElem);
		return printType(pBaseType, str.data());
	} 

	if ( tag == SymTagFunctionType ) {
		return L"void *";  // was L"Function" but...
	}

	if ( tag == SymTagCustomType ) {
		DWORD id = 0;
		DWORD rec = 0;
		GUID guid = GUID_NULL;
		if ( pType->get_guid(&guid) == S_OK ) {
			const int maxGUIDStrLen = 64 + 1;
			std::vector<wchar_t> guidStr(maxGUIDStrLen);
			if (StringFromGUID2(guid, guidStr.data(), maxGUIDStrLen) > 0) {
				return guidStr.data();
			}
		} 
		else if ( pType->get_oemId( &id ) == S_OK && pType->get_oemSymbolId( &rec ) == S_OK ) {
			const size_t strLen = 256;		// wag_for_2_hex_numbers "0xNNNNN:0xNNNNN"
			wchar_t str[strLen] = {};
			if (str != NULL) {
				swprintf_s(str, L"0x%x:0x%x", id, rec);
				return str;
			}
		}
		return L"";
	}

	if ( !name.empty() ) {
		return name + suffix;
	} 

	return L"Undefined";
}

void printScopeName( IDiaSymbol& pscope ) {
	printf("<scope name=\"%S\" tag=\"%S\" />\n", getName( pscope ).c_str(), getTagAsString( pscope ).c_str());
}

void printNameFromScope( IDiaSymbol& scope, IDiaEnumSymbols& myEnum ) {

	CComPtr<IDiaSymbol> pSym;
	DWORD celt = 0;
	while ( myEnum.Next( 1, &pSym, &celt ) == S_OK && celt == 1 ) {
		printf( "\t%S %S found in ", getTagAsString(*pSym).c_str(), getName(*pSym).c_str() );
		printScopeName( scope );
		printf( "\n" );
		pSym = 0;
	}
}

