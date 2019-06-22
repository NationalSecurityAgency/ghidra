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
#include <vector>
#include <comutil.h>
#include <atlcomcli.h>

#pragma comment(lib, "comsuppw.lib") // bstr_t

const static std::wstring SYMBOL_TAG_STRINGS [] = {
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

const static std::wstring UDT_KIND_STRINGS [] = {
		L"Structure",
		L"Class",
		L"Union",
		L"Interface"
};

const static std::wstring DATA_KIND_STRINGS [] = {
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

const static std::wstring BASIC_TYPE_STRINGS [] = {
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
		L"HRESULT",
		L"char16_t",
		L"char32_t"
};

std::wstring getName(IDiaSymbol& pSymbol) {
    bstr_t name;
    if (SUCCEEDED(pSymbol.get_name(name.GetAddress()))) {
        const std::wstring wstrName = std::wstring(name.GetBSTR(), name.length());
        if (wstrName.empty()) {
            return escapeXmlEntities(L"NONAME");
        }

        if (wstrName.find(L"unnamed-tag") != std::wstring::npos) {
            DWORD symIndexId = 0;
            if (FAILED(pSymbol.get_symIndexId(&symIndexId))) {
                symIndexId = 0;
            }
            const size_t length = 20;	// length of: "<unnamed_NNNN>\0" + 1 extra
            std::vector<wchar_t> str(20);
            swprintf_s(str.data(), length, L"<unnamed_%04x>", symIndexId);
            return escapeXmlEntities(str.data());
        }
        
        DWORD locType = 0;
        ULONGLONG len = 0;
        if (SUCCEEDED(pSymbol.get_locationType(&locType)) &&
            locType == LocIsBitField &&
            SUCCEEDED(pSymbol.get_length(&len))) {
            const size_t length = wstrName.length() + 4 + 32;	// length of: name + ":0x\0" + wag_hex_numeric_str_len
            std::vector<wchar_t> str(length);
            swprintf_s(str.data(), length, L"%ws:0x%I64x", wstrName.c_str(), len);
            return escapeXmlEntities(str.data());
        }

        return escapeXmlEntities(wstrName);
    }
    return std::wstring();
}

std::wstring getUndecoratedName(IDiaSymbol& pSymbol) {
	bstr_t name;
	if (SUCCEEDED(pSymbol.get_undecoratedName( name.GetAddress() ))) {
        return escapeXmlEntities(std::wstring(name.GetBSTR(), name.length()));
	}
	return L"";
}
DWORD getRVA(IDiaSymbol& pSymbol) {
	DWORD rva = 0;
	pSymbol.get_relativeVirtualAddress( &rva );
	return rva;
}
ULONGLONG getLength(IDiaSymbol& pSymbol) {
	ULONGLONG len = 0;
	pSymbol.get_length( &len );
	return len;
}
DWORD getTag(IDiaSymbol& pSymbol) {
	DWORD tag = 0;
	pSymbol.get_symTag( &tag );
	return tag;
}

std::wstring getTagAsString(IDiaSymbol& pSymbol) {
	return SYMBOL_TAG_STRINGS[getTag(pSymbol)];
}
DWORD getKind(IDiaSymbol& pSymbol) {
	DWORD kind = 0;
	pSymbol.get_dataKind( &kind );
	return kind;
}
DWORD getUdtKind(IDiaSymbol& pSymbol) {
	DWORD kind = 0;
	pSymbol.get_udtKind( &kind );
	return kind;
}
std::wstring getKindAsString(IDiaSymbol& pSymbol) {
	const DWORD tag = getTag(pSymbol);
	if (tag == SymTagUDT) {
		return UDT_KIND_STRINGS[getUdtKind(pSymbol)];
	}
	return DATA_KIND_STRINGS[getKind(pSymbol)];
}

LONG getOffset(IDiaSymbol& pSymbol) {
	LONG offset = 0;
	pSymbol.get_offset( &offset );
	return offset;
}
DWORD getIndex(IDiaSymbol& pSymbol) {
	DWORD index = 0;
	pSymbol.get_symIndexId( &index );
	return index;
}

std::wstring getValue(IDiaSymbol& pSymbol) {
	if (getKind(pSymbol) == DataIsConstant) {
		VARIANT value;
		HRESULT hr = pSymbol.get_value( &value );
		if (hr == S_OK) {
			return printVariant( value );
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

CComPtr<IDiaSymbol> getType(IDiaSymbol& pSymbol) {
    CComPtr<IDiaSymbol> pBaseType;
	if (SUCCEEDED(pSymbol.get_type( &pBaseType ))) {
		return pBaseType;
	}
	return NULL;
}
std::wstring getTypeAsString(IDiaSymbol& pSymbol) {
    std::wstring typeStr ;
    CComPtr<IDiaSymbol> pType;
	if (SUCCEEDED(pSymbol.get_type( &pType ))) {
		typeStr = printType( pType, L"" );
	}
	else {
		typeStr = L"";
	}
	return typeStr;
}

static DWORD getBaseType(IDiaSymbol& pSymbol) {
	if (getTag(pSymbol) == SymTagBaseType) {
		DWORD baseType = btNoType;
		if (FAILED(pSymbol.get_baseType(&baseType))) {
			return btNoType;
		}
		return baseType;
	}
	return btNoType;
}
std::wstring getBaseTypeAsString(IDiaSymbol& pSymbol) {
	const ULONGLONG len = getLength(pSymbol);
	const DWORD bt = getBaseType(pSymbol);
    switch(bt) {
		case btInt:
			switch(len) {
				case 1: return L"char";
				case 2: return L"short";
				case 4: return L"int";
				case 8: return L"__int64";
			}
			break;
		case btUInt:
			switch(len) {
				case 1: return L"uchar";
				case 2: return L"ushort";
				case 4: return L"uint";
				case 8: return L"__uint64";
			}
			break;
        case btFloat:
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
