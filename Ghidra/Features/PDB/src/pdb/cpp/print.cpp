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

// Returns a mixture of static strings and allocated strings.
// Abandon all hope of memory management, ye who enter here
wchar_t * printVariant( VARIANT & v ) {
	
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

	size_t printfFormatBufferLen = 100;
	wchar_t * variant = (wchar_t *)calloc(printfFormatBufferLen, sizeof(wchar_t));
	switch( v.vt ) {
		case VT_ARRAY://Indicates a SAFEARRAY pointer. 
			swprintf(variant, L"%d", v.parray);//TODO
			return variant;
		case VT_BYREF://Indicates that a value is a reference. 
			swprintf(variant, L"%d", v.cVal);//TODO
			return variant;
		case VT_CY://Indicates a currency value. 
			swprintf(variant, L"%f", v.cyVal);
			return variant;
		case VT_DATE://Indicates a DATE value. 
			swprintf(variant, L"%d", v.date);
			return variant;
		case VT_DISPATCH://Indicates an IDispatch pointer. 
			swprintf(variant, L"%d", v.pdispVal);
			return variant;
		case VT_ERROR://Indicates an SCODE. 
			swprintf(variant, L"0x%x", v.scode);
			return variant;
		case VT_I1://CHAR
			swprintf(variant, L"%d", v.cVal);
			return variant;
		case VT_I2://SHORT
			swprintf(variant, L"%d", v.iVal);
			return variant;
		case VT_I4://LONG
			swprintf(variant, L"%d", v.lVal );
			return variant;
		case VT_I8: //LONGLONG
			swprintf(variant, L"%ld", v.llVal );
			return variant;
		case VT_INT://INT
			swprintf(variant, L"%d", v.intVal);
			return variant;
		case VT_R4://Indicates a float value. 
			swprintf(variant, L"%f", v.fltVal);
			return variant;
		case VT_R8://Indicates a double value. 
			swprintf(variant, L"%f", v.dblVal);
			return variant;
		case VT_UI1://BYTE
			swprintf(variant, L"%d", v.bVal);
			return variant;
		case VT_UI2://USHORT
			swprintf(variant, L"%d", v.uiVal);
			return variant;
		case VT_UI4://ULONG
			swprintf(variant, L"%d", v.ulVal);
			return variant;
		case VT_UI8://ULONGLONG
			swprintf(variant, L"%ld", v.ullVal);
			return variant;
		case VT_UINT://UINT
			swprintf(variant, L"%d", v.uintVal);
			return variant;
		case VT_UNKNOWN://Indicates an IUnknown pointer. 
			swprintf(variant, L"%d", v.punkVal);
			return variant;
		case VT_VARIANT://Indicates a VARIANT far pointer. 
			swprintf(variant, L"%d", v.pvarVal);
			return variant;

		default:
			return L"unknown";
	}
}

void printBound( IDiaSymbol* pBound ) {

	DWORD tag = 0;
	BSTR name;
	DWORD kind;
	pBound->get_symTag( &tag );
	pBound->get_locationType( &kind );
	if ( tag == SymTagData && kind == LocIsConstant ) {
		//TODO
		//CComVariant v;
		//pBound->get_value( &v );
		//printVariant( v );
	} 
	else if ( pBound->get_name( &name ) == S_OK ) {
		printf( "%ws", name );
	}
}

// Returns mixture of allocated and static strings
BSTR printType( IDiaSymbol * pType, BSTR suffix ) {
	if (pType == NULL) {
		return L"";
	}
	BSTR name = getName(pType);
	DWORD tag = getTag(pType);

	if ( tag == SymTagPointerType ) {
		IDiaSymbol * pBaseType;
		if ( pType->get_type( &pBaseType ) == S_OK ) {
			size_t length = wcslen(suffix) + 3;	// length of: suffix + " *\0"
			wchar_t * str = (wchar_t *)calloc(length, sizeof(wchar_t));
			swprintf(str, L"%ws *", suffix );
			return (BSTR)printType( pBaseType, (BSTR)str );
		}
		else {
			return L"";
		}
	} 

	if ( tag == SymTagBaseType ) {
		BSTR bt = getBaseTypeAsString( pType );
		size_t length = wcslen(bt) + wcslen(suffix) + 1;	// length of: bt + suffix + "\0"
		wchar_t * str = (wchar_t *)calloc(length, sizeof(wchar_t));
		swprintf(str, L"%ws%ws", bt, suffix );
		return str;
	}

	if ( tag == SymTagArrayType ) {
		IDiaSymbol * pBaseType = getType( pType );
		if ( pBaseType == NULL ) {
			return L"";
		}
		ULONGLONG lenArray = getLength( pType );
		ULONGLONG lenElem  = getLength( pBaseType );
		if (lenElem == 0) {//prevent divide by zero...
			lenElem = lenArray;
		}
		size_t strLen = wcslen(suffix) + 64 + 3;	// length of suffix + wag_for_numeric_value + "[]\0" 
		wchar_t * str = (wchar_t *)calloc(strLen, sizeof(wchar_t));
		swprintf(str, L"%ws[%ld]", suffix, lenArray/lenElem );

		return printType( pBaseType, (BSTR)str);
	} 

	if ( tag == SymTagFunctionType ) {
		return L"void *";  // was L"Function" but...
	}

	if ( tag == SymTagCustomType ) {
		DWORD id;
		DWORD rec;
		GUID guid;
		if ( pType->get_guid( &guid ) == S_OK ) {
			size_t maxGUIDStrLen = 64;
			wchar_t * guidStr = (wchar_t *)calloc(maxGUIDStrLen, sizeof(wchar_t));
			StringFromGUID2(guid, guidStr, maxGUIDStrLen);
			return (BSTR)guidStr;
		} 
		else if ( pType->get_oemId( &id ) == S_OK && pType->get_oemSymbolId( &rec ) == S_OK ) {
			size_t strLen = 256;		// wag_for_2_hex_numbers "0xNNNNN:0xNNNNN"
			wchar_t * str = (wchar_t *)calloc(strLen, sizeof(wchar_t));
			swprintf(str, L"0x%x:0x%x", id, rec);
			return (BSTR)str;
		}
		return L"";
	}

	if ( name != NULL ) {
		size_t length = wcslen(name) + wcslen(suffix) + 1;	// length of name + suffix + "\0"
		wchar_t * str = (wchar_t *)calloc(length, sizeof(wchar_t));
		swprintf(str, L"%ws%ws", name, suffix);
		return (BSTR)str;
	} 

	return L"Undefined";
}

void printScopeName( IDiaSymbol* pscope ) {
	printf("<scope name=\"%ws\" tag=\"%ws\" />\n", getName( pscope ), getTagAsString( pscope ));
}

void printNameFromScope( wchar_t* name, IDiaSymbol* pscope, IDiaEnumSymbols* pEnum ) {

	IDiaSymbol * pSym;
	DWORD celt;
	while ( SUCCEEDED( pEnum->Next( 1, &pSym, &celt ) ) && celt == 1 ) {
		BSTR  name = getName( pSym );
		BSTR  tag  = getTagAsString( pSym );
		wprintf( L"\t%ws %ws found in ", tag, name );
		printScopeName( pscope );
		wprintf( L"\n" );
		pSym = 0;
	}
}

