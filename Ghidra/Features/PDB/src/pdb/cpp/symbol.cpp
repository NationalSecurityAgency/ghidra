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

std::wstring getName(IDiaSymbol& symbol) {
	bstr_t name;
	if (symbol.get_name(name.GetAddress()) == S_OK) {
		const std::wstring wstrName = std::wstring(name.GetBSTR(), name.length());
		if (wstrName.empty()) {
			return escapeXmlEntities(L"NONAME");
		}

		if (wstrName.find(L"unnamed-tag") != std::wstring::npos) {
			DWORD symIndexId = 0;
			if (symbol.get_symIndexId(&symIndexId) != S_OK) {
				symIndexId = 0;
			}
			const size_t length = 20;	// length of: "<unnamed_NNNN>\0" + 1 extra
			std::vector<wchar_t> str(length);
			swprintf_s(str.data(), length, L"<unnamed_%04x>", symIndexId);
			return escapeXmlEntities(str.data());
		}

		DWORD locType = 0;
		ULONGLONG len = 0;
		DWORD bitPos = 0;
		if (symbol.get_locationType(&locType) == S_OK &&
			locType == LocIsBitField &&
			symbol.get_length(&len) == S_OK &&
			symbol.get_bitPosition(&bitPos) == S_OK) {
			// allocate length of: name + ":0x" + len + ":0x" + bitPos + "\0" 
			const size_t length = wstrName.length() + 70;	
			std::vector<wchar_t> str(length);
			swprintf_s(str.data(), length, L"%ws:0x%I64x:0x%x", wstrName.c_str(), len, bitPos);
			return escapeXmlEntities(str.data());
		}

		return escapeXmlEntities(wstrName);
	}
	return std::wstring();
}

std::wstring getUndecoratedName(IDiaSymbol& symbol) {
	bstr_t name;
	if (symbol.get_undecoratedName(name.GetAddress()) == S_OK) {
		// May also return S_FALSE which is not failure, however in this case there is no name
		return escapeXmlEntities(std::wstring(name.GetBSTR(), name.length()));
	}
	return L"";
}

DWORD getRVA(IDiaSymbol& symbol) {
	DWORD rva = 0;
	symbol.get_relativeVirtualAddress( &rva );
	return rva;
}
ULONGLONG getLength(IDiaSymbol& symbol) {
	ULONGLONG len = 0;
	symbol.get_length( &len );
	return len;
}
DWORD getTag(IDiaSymbol& symbol) {
	DWORD tag = 0;
	symbol.get_symTag( &tag );
	return tag;
}

std::wstring getTagAsString(IDiaSymbol& symbol) {
	const DWORD tag = getTag(symbol);
	if (tag > _countof(SYMBOL_TAG_STRINGS) - 1)	{
		return L"";
	}
	return SYMBOL_TAG_STRINGS[tag];
}
DWORD getKind(IDiaSymbol& symbol) {
	DWORD kind = 0;
	symbol.get_dataKind( &kind );
	return kind;
}
DWORD getUdtKind(IDiaSymbol& symbol) {
	DWORD kind = 0;
	symbol.get_udtKind( &kind );
	return kind;
}
std::wstring getKindAsString(IDiaSymbol& symbol) {
	const DWORD tag = getTag(symbol);
	if (tag == SymTagUDT) {
		const DWORD kind = getUdtKind(symbol);
		if (kind < _countof(UDT_KIND_STRINGS)) {
			return UDT_KIND_STRINGS[kind];
		}
		return L"";
	}
	const DWORD dataKind = getKind(symbol);
	if (dataKind < _countof(DATA_KIND_STRINGS)) {
		return DATA_KIND_STRINGS[dataKind];
	}
	return L"";
}

LONG getOffset(IDiaSymbol& symbol) {
	LONG offset = 0;
	symbol.get_offset( &offset );
	return offset;
}
DWORD getIndex(IDiaSymbol& symbol) {
	DWORD index = 0;
	symbol.get_symIndexId( &index );
	return index;
}

std::wstring getValue(IDiaSymbol& symbol) {
	if (getKind(symbol) == DataIsConstant) {
		VARIANT value;
		value.vt = VT_EMPTY;
		if (symbol.get_value( &value ) == S_OK) {
			return printVariant( value );
		}
	}
	return L"";
}
/*
BSTR getBaseTypeName(IDiaSymbol * symbol) {
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

CComPtr<IDiaSymbol> getType(IDiaSymbol& symbol) {
	CComPtr<IDiaSymbol> pBaseType;
	if (symbol.get_type( &pBaseType ) == S_OK) {
		return pBaseType;
	}
	return NULL;
}
std::wstring getTypeAsString(IDiaSymbol& symbol) {
	std::wstring typeStr ;
	CComPtr<IDiaSymbol> pType;
	if (symbol.get_type( &pType ) == S_OK) {
		typeStr = printType( pType, L"" );
	}
	else {
		typeStr = L"";
	}
	return typeStr;
}

static DWORD getBaseType(IDiaSymbol& symbol) {
	if (getTag(symbol) == SymTagBaseType) {
		DWORD baseType = btNoType;
		if (symbol.get_baseType(&baseType) != S_OK) {
			return btNoType;
		}
		return baseType;
	}
	return btNoType;
}
std::wstring getBaseTypeAsString(IDiaSymbol& symbol) {
	const ULONGLONG len = getLength(symbol);
	const DWORD bt = getBaseType(symbol);
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
	if (bt < _countof(BASIC_TYPE_STRINGS)) {
		return escapeXmlEntities(BASIC_TYPE_STRINGS[bt]);
	}
	return L"";
}

bool isScopeSym( DWORD tag )
{
	if ( tag > SymTagNull && tag < SymTagMax ) {
		return fTagScopes[ tag ];
	}
	assert( false );
	return false;
}
