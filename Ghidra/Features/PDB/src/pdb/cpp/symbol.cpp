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
#include "symbol.h"
#include "xml.h"
#include "print.h"
#include "pdb.h"

static wchar_t* SYMBOL_TAG_STRINGS [] = {
		L"",
		L"Executable",
		L"Compiland", 
		L"CompilandDetails", 
		L"CompilandEnv",
		L"Function", 
		L"Block",
		L"Data",
		L"Annotation", 
		L"Label", 
		L"PublicSymbol", 
		L"UserDefinedType", 
		L"Enum", 
		L"FunctionType", 
		L"PointerType", 
		L"ArrayType", 
		L"BaseType", 
		L"Typedef", 
		L"BaseClass",
		L"Friend",
		L"FunctionArgType", 
		L"FuncDebugStart", 
		L"FuncDebugEnd",
		L"UsingNamespace", 
		L"VTableShape",
		L"VTable",
		L"Custom",
		L"Thunk",
		L"CustomType",
		L"ManagedType",
  		L"Dimension",
  		L"CallSite",
  		L"InlineSite",
  		L"BaseInterface",
  		L"VectorType",
  		L"MatrixType",
  		L"HLSLType",
  		L"Caller",
  		L"Callee",
  		L"Export",
  		L"HeapAllocationSite",
  		L"CoffGroup",
  		L"Inlinee",
		L""
};

static bool fTagScopes [] = {
		false,
		true,
		true, 
		false, 
		false,
		true, 
		true,
		false,
		false, 
		false, 
		false, 
		false, 
		false, 
		false, 
		false, 
		false, 
		false, 
		false, 
		false,
		false,
		false, 
		false, 
		false,
		false, 
		false,
		false,
		false,
		false,
		false,
		false,
		false, 
		false, 
		false, 
		false, 
		false, 
		false, 
		false, 
		false, 
		false, 
		false, 
		false,
		false,
		false, 
		false
};

static wchar_t * UDT_KIND_STRINGS [] = {
		L"Structure",
		L"Class",
		L"Union",
		L"Interface"
};

static wchar_t* DATA_KIND_STRINGS [] = {
		L"Unknown",
		L"Local",
		L"StaticLocal",
		L"Parameter",
		L"ObjectPointer",
		L"FileStatic",
		L"Global",
		L"Member",
		L"StaticMember",
		L"Constant"
};

static wchar_t* BASIC_TYPE_STRINGS [] = {
		L"<NoType>",
		L"void",
		L"char",
		L"wchar",
		L"char",//4
		L"uchar",//5
		L"int",
		L"uint",
		L"float",
		L"<BCD>",
		L"bool",
		L"short",//11
		L"ushort",//12
		L"long",
		L"ulong",
		L"__int8",//15
		L"__int16",//16
		L"__int32",//17
		L"__int64",//18
		L"__int128",//19
		L"unsigned __int8",//20
		L"unsigned __int16",//21
		L"unsigned __int32",//22
		L"unsigned __int64",//23
		L"unsigned __int128",//24
		L"<currency>",
		L"<date>",
		L"VARIANT",
		L"<complex>",
		L"<bit>",
		L"BSTR",
		L"HRESULT"
};

BSTR getName(IDiaSymbol * pSymbol) {
	BSTR name, escapedName;
	DWORD symIndexId, locType;
	ULONGLONG len;
	if (pSymbol->get_name( &name ) == 0) {
		if (wcscmp(name, L"") == 0) {
			size_t length = 7;	// length of: "NONAME\0"
			wchar_t * str = (wchar_t *)calloc(length, sizeof(wchar_t));
			swprintf(str, L"NONAME");
			escapedName = escapeXmlEntities(str);
		} else
		if(wcsstr(name, L"unnamed-tag") != NULL){
			if(pSymbol->get_symIndexId(&symIndexId) != 0){
				symIndexId = 0;
			}
			size_t length = 16;	// length of: "<unnamed_NNNN>\0" + 1 extra
			wchar_t * str = (wchar_t *)calloc(length, sizeof(wchar_t));
			swprintf(str, L"<unnamed_%04x>", symIndexId);
			escapedName = escapeXmlEntities(str);
		} else
		if(pSymbol->get_locationType(&locType) == 0 &&
			locType == LocIsBitField && 
			pSymbol->get_length(&len) == 0){
			size_t length = wcslen(name) + 4 + 32;	// length of: name + ":0x\0" + wag_hex_numeric_str_len
			wchar_t * str = (wchar_t *)calloc(length, sizeof(wchar_t));
			swprintf(str, L"%ws:0x%x", name, len);
			escapedName = escapeXmlEntities(str);
		} else {
			escapedName = escapeXmlEntities(name);
		}
		SysFreeString(name);
		return escapedName;
	}
	return NULL;
}
BSTR getUndecoratedName(IDiaSymbol * pSymbol) {
	BSTR name;
	if (pSymbol->get_undecoratedName( &name ) == 0) {
        BSTR escapedName = escapeXmlEntities(name);
		SysFreeString(name);
		return escapedName;
	}
	return L"";
}
DWORD getRVA(IDiaSymbol * pSymbol) {
	DWORD rva;
	pSymbol->get_relativeVirtualAddress( &rva );
	return rva;
}
ULONGLONG getLength(IDiaSymbol * pSymbol) {
	ULONGLONG len = 0;
	pSymbol->get_length( &len );
	return len;
}
DWORD getTag(IDiaSymbol * pSymbol) {
	DWORD tag;
	pSymbol->get_symTag( &tag );
	return tag;
}
BSTR getTagAsString(IDiaSymbol * pSymbol) {
	return SYMBOL_TAG_STRINGS[getTag(pSymbol)];
}
DWORD getKind(IDiaSymbol * pSymbol) {
	DWORD kind;
	pSymbol->get_dataKind( &kind );
	return kind;
}
DWORD getUdtKind(IDiaSymbol * pSymbol) {
	DWORD kind;
	pSymbol->get_udtKind( &kind );
	return kind;
}
BSTR getKindAsString(IDiaSymbol * pSymbol) {
	DWORD tag = getTag(pSymbol);
	if (tag == SymTagUDT) {
		return UDT_KIND_STRINGS[getUdtKind(pSymbol)];
	}
	return DATA_KIND_STRINGS[getKind(pSymbol)];
}
/*
DWORD getSection(IDiaSymbol * pSymbol) {
	DWORD section;
	pSymbol->get_addressSection( &section );
	return section;
}
*/
LONG getOffset(IDiaSymbol * pSymbol) {
	LONG offset;
	pSymbol->get_offset( &offset );
	return offset;
}
DWORD getIndex(IDiaSymbol * pSymbol) {
	DWORD index;
	pSymbol->get_symIndexId( &index );
	return index;
}

wchar_t * getValue(IDiaSymbol * pSymbol) {
	if (getKind(pSymbol) == DataIsConstant) {
		VARIANT value;
		HRESULT hr = pSymbol->get_value( &value );
		if (hr == S_OK) {
			return printVariant( value );
			//return value.bstrVal;
		}
	}
	return L"";
}
/*
BSTR getBaseTypeName(IDiaSymbol * pSymbol) {
	IDiaSymbol * pBaseType;
	if (pType->get_type( &pBaseType ) != 0) {
		return NULL;
	}

	DWORD tag = getTag(pBaseType);

	if ( tag == SymTagBaseType ) {
		DWORD bt = getBaseType( pType );
		return BASIC_TYPE_STRINGS[bt];
	}

	return getBaseTypeName(pBaseType);
}
*/

IDiaSymbol * getType(IDiaSymbol * pSymbol) {
	IDiaSymbol * pBaseType;
	if (pSymbol->get_type( &pBaseType ) == 0) {
		return pBaseType;
	}
	return NULL;
}
BSTR getTypeAsString(IDiaSymbol * pSymbol) {
	BSTR typeStr ;
	IDiaSymbol * pType;
	if (pSymbol->get_type( &pType ) == 0) {
		typeStr = printType( pType, L"" );
	}
	else {
		typeStr = L"";
	}
	return typeStr;
}

DWORD getBaseType(IDiaSymbol * pSymbol) {
	if (getTag(pSymbol) == SymTagBaseType) {
		DWORD baseType;
		pSymbol->get_baseType( &baseType );
		return baseType;
	}
	return -1;
}
BSTR getBaseTypeAsString(IDiaSymbol * pSymbol) {
	ULONGLONG len = getLength(pSymbol);
	DWORD bt = getBaseType(pSymbol);
    switch(bt) {
		case 6 :
			switch(len) {
				case 1: return L"char";
				case 2: return L"short";
				case 4: return L"int";
				case 8: return L"__int64";
			}
			break;
		case 7 :
			switch(len) {
				case 1: return L"uchar";
				case 2: return L"ushort";
				case 4: return L"uint";
				case 8: return L"__uint64";
			}
			break;
        case 8 :
			switch(len) {
				case 4: return L"float";
				case 8: return L"double";
			}
			break;
	}
	return escapeXmlEntities(BASIC_TYPE_STRINGS[bt]);
}

bool isScopeSym( DWORD tag )
{
	if ( tag > SymTagNull && tag < SymTagMax ) {
		return fTagScopes[ tag ];
	}
	assert( false );
	return false;
}
