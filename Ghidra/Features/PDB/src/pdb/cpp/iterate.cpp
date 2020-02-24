/* ###
 * IP: GHIDRA
 * NOTE: Added option to omit unused information from output.
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
#include "iterate.h"

static void iterateEnumMembers(IDiaSymbol& symbol) {
	DWORD celt = 0;
	CComPtr<IDiaEnumSymbols> pEnum;
	CComPtr<IDiaSymbol> pMember;
	symbol.findChildren(SymTagNull, NULL, nsNone, &pEnum);
	if (pEnum == NULL) {
		return;
	}
	while (1) {
		if (pEnum->Next( 1, &pMember, &celt ) != S_OK ) {
			break;
		}
		if (celt != 1) {
			break;
		}
		std::wstring name = getName(*pMember);
		std::wstring value = getValue(*pMember);
		printf("%S<member name=\"%S\" value=\"%S\" />\n", indent(12).c_str(), name.c_str(), value.c_str());
		pMember = 0;
	}
}

void iterateEnums(PDBApiContext& ctx) {
	DWORD celt = 0;
	CComPtr<IDiaEnumSymbols> pEnum;
	CComPtr<IDiaSymbol> pSymbol;
	ctx.Global().findChildren(SymTagEnum, NULL, nsNone, &pEnum);
	if (pEnum == NULL) {
		return;
	}
	printf("%S<enums>\n", indent(4).c_str());
	while ( 1 ) {
		if (pEnum->Next( 1, &pSymbol, &celt ) != S_OK ) {
			break;
		}
		if (celt != 1) {
			break;
		}

		const DWORD tag = getTag(*pSymbol);
		if (tag != SymTagEnum) {//do not delete
			continue;
		}

		printf("%S<enum name=\"%S\" type=\"%S\" length=\"0x%I64x\" >\n", indent(8).c_str(), getName(*pSymbol).c_str(), getTypeAsString(*pSymbol).c_str(), getLength(*pSymbol));

		iterateEnumMembers(*pSymbol);

		printf("%S</enum>\n", indent(8).c_str());
		pSymbol = 0;
	}
	printf("%S</enums>\n", indent(4).c_str());
}

static void iterateMembers(IDiaSymbol& symbol) {
	DWORD celt = 0;
	CComPtr<IDiaEnumSymbols> pEnum;
	symbol.findChildren(SymTagNull, NULL, nsNone, &pEnum);
	if (pEnum == NULL) {
		return;
	}
	while (1) {
		CComPtr<IDiaSymbol> pMember;
		if (pEnum->Next(1, &pMember, &celt) != S_OK ) {
			break;
		}
		if (celt != 1) {
			break;
		}

		printf("%S<member name=\"%S\" datatype=\"%S\" offset=\"0x%x\" kind=\"%S\" length=\"0x%I64x\" />\n",
			indent(12).c_str(),
			getName(*pMember).c_str(),
			getTypeAsString(*pMember).c_str(),
			getOffset(*pMember),
			getKindAsString(*pMember).c_str(),
			getLength(*pMember));
	}
}

void iterateDataTypes(PDBApiContext& ctx) {
	DWORD celt = 0;
	CComPtr<IDiaEnumSymbols> pEnum;
	ctx.Global().findChildren(SymTagUDT, NULL, nsNone/*nsfCaseInsensitive|nsfUndecoratedName*/, &pEnum);
	if (pEnum == NULL) {
		return;
	}
	printf("%S<datatypes>\n", indent(4).c_str());
	while (1) {
		CComPtr<IDiaSymbol> pSymbol;

		if ( pEnum->Next(1, &pSymbol, &celt) != S_OK ) {
			break;
		}
		if (celt != 1) {
			break;
		}

		const DWORD tag = getTag(*pSymbol);
		if (tag != SymTagUDT) {//do not delete
			continue;
		}

		if (getUdtKind(*pSymbol) == UdtClass) {
			continue;
		}

		const ULONGLONG len = getLength(*pSymbol);
//		if (len == 0) {
//			continue;
//		}

		printf("%S<datatype name=\"%S\" kind=\"%S\" length=\"0x%I64x\" >\n", indent(8).c_str(), getName(*pSymbol).c_str(), getKindAsString(*pSymbol).c_str(), len);

		iterateMembers(*pSymbol);

		printf("%S</datatype>\n", indent(8).c_str());
		pSymbol = 0;
	}
	printf("%S</datatypes>\n", indent(4).c_str());
}

void iterateTypedefs(PDBApiContext& ctx) {
	DWORD celt = 0;
	CComPtr<IDiaEnumSymbols> pEnum;
	ctx.Global().findChildren(SymTagTypedef, NULL, nsNone/*nsfCaseInsensitive|nsfUndecoratedName*/, &pEnum);
	if (pEnum == NULL) {
		return;
	}
	printf("%S<typedefs>\n", indent(4).c_str());
	while ( 1 ) {
		CComPtr<IDiaSymbol> pSymbol;
		if (pEnum->Next( 1, &pSymbol, &celt ) != S_OK ) {
			break;
		}
		if (celt != 1) {
			break;
		}

		const DWORD tag = getTag(*pSymbol);
		if (tag != SymTagTypedef) {//do not delete
			continue;
		}

		printf("%S<typedef name=\"%S\" basetype=\"%S\" />\n", indent(8).c_str(), getName(*pSymbol).c_str(), getTypeAsString(*pSymbol).c_str());
	}
	printf("%S</typedefs>\n", indent(4).c_str());
}

void iterateClasses(PDBApiContext& ctx) {
	DWORD celt = 0;
	CComPtr<IDiaEnumSymbols> pEnum;
	ctx.Global().findChildren(SymTagUDT, NULL, nsNone/*nsfCaseInsensitive|nsfUndecoratedName*/, &pEnum);
	if (pEnum == NULL) {
		return;
	}
	printf("%S<classes>\n", indent(4).c_str());
	while ( 1 ) {
		CComPtr<IDiaSymbol> pSymbol;
		if (pEnum->Next( 1, &pSymbol, &celt ) != S_OK ) {
			break;
		}
		if (celt != 1) {
			break;
		}

		const DWORD tag = getTag(*pSymbol);
		if (tag != SymTagUDT) {//do not delete
			continue;
		}

		if (getUdtKind(*pSymbol) != UdtClass) {
			continue;
		}

		const ULONGLONG len  = getLength(*pSymbol);
//		if ( len == 0 ) {
//			continue;
//		}

		printf("%S<class name=\"%S\" length=\"0x%I64x\" >\n", indent(8).c_str(), getName(*pSymbol).c_str(), len);

		iterateMembers(*pSymbol);

		printf("%S</class>\n", indent(8).c_str());
		pSymbol = 0;
	}
	printf("%S</classes>\n", indent(4).c_str());
}

// This method still leaks memory--seemingly in the pEnum->Next() for
// certain symbol types (e.g., tag == 32 (inline))
void dumpFunctionStackVariables(IDiaSymbol* symbol, IDiaSession& session )
{
	CComPtr<IDiaSymbol> pBlock;

	const DWORD address = getRVA(*symbol);
	HRESULT hr = session.findSymbolByRVA( address, SymTagBlock, &pBlock );
	if( hr == S_FALSE ) {
		pBlock = symbol;
	}
	else if ( FAILED(hr) ){
		fatal( "Failed to find symbols by RVA" );
	}

	for ( ; pBlock != NULL; ) {
		CComPtr<IDiaEnumSymbols> pEnum;
		// Local data search
		if ( FAILED( pBlock->findChildren( SymTagNull, NULL, nsNone, &pEnum ) ) ) {
			fatal( "Local scope findChildren failed" );
		}
		CComPtr<IDiaSymbol> pSymbol;
		DWORD tag;
		DWORD celt;
		while (pEnum != NULL && pEnum->Next(1, &pSymbol, &celt) == S_OK && celt == 1) {
			pSymbol->get_symTag( &tag );
			if ( tag == SymTagData ) {
				printf("%S<stack_variable name=\"%S\" kind=\"%S\" offset=\"0x%x\" datatype=\"%S\" length=\"0x%I64x\" />\n", 
							indent(12).c_str(),
							getName(*pSymbol).c_str(),
							getKindAsString(*pSymbol).c_str(), 
							getOffset(*pSymbol),
							getTypeAsString(*pSymbol).c_str(),
							getLength(*pSymbol));
			} 
			else if ( tag == SymTagAnnotation ) {
				/*
				IDiaEnumSymbols * pValues;
				// Local data search
				wprintf( L"\tAnnotation:\n" );
				if ( FAILED( pSymbol->findChildren( SymTagNull, NULL, nsNone, &pValues ) ) ) {
					fatal( "Annotation findChildren failed" );
				}
				pSymbol = NULL;
				while ( pValues != NULL && pValues->Next( 1, &pSymbol, &celt ) == S_OK && celt == 1 ) {
					//TODO
					//CComVariant value;
					//if ( pSymbol->get_value( &value ) != S_OK ) {
					//	fatal( "No value for annotation data." );
					//}
					//wprintf( L"\t\t%ws\n", value.bstrVal );
					pSymbol = NULL;
				}
				*/
			}
			pSymbol = NULL;
		}
		pBlock->get_symTag( &tag ); 
		if ( tag == SymTagFunction ) {  // Stop at function scope.
			break;
		}
		// Move to lexical parent.
		CComPtr<IDiaSymbol> pParent;
		if ( pBlock->get_lexicalParent( &pParent ) == S_OK ) {
			pBlock = pParent;
		} 
		else {
			break;
			//fatal( "Finding lexical parent failed." );
		}
	};
}

void dumpFunctionLines( IDiaSymbol& symbol, IDiaSession& session )
{
	ULONGLONG length = 0;
	DWORD isect = 0;
	DWORD offset = 0;
	symbol.get_addressSection( &isect );
	symbol.get_addressOffset( &offset );
	symbol.get_length( &length );
	if ( isect == 0 || length <= 0 ) {
		return;
	}

	CComPtr<IDiaEnumLineNumbers> pLines;
	if (session.findLinesByAddr( isect, offset, static_cast<DWORD>( length ), &pLines ) != S_OK ) {
		return;
	}

	DWORD celt = 0;
	while ( 1 ) {
		CComPtr<IDiaLineNumber> pLine;
		if (pLines->Next( 1, &pLine, &celt ) != S_OK) {
			break;
		}
		if (celt != 1) {
			break;
		}

		CComPtr<IDiaSymbol> pComp;
		pLine->get_compiland( &pComp );

		CComPtr<IDiaSourceFile> pSrc;
		pLine->get_sourceFile( &pSrc );

		bstr_t sourceFileName;
		pSrc->get_fileName(sourceFileName.GetAddress());

		DWORD addr = 0;
		pLine->get_relativeVirtualAddress( &addr );

		DWORD start = 0;
		pLine->get_lineNumber( &start );
		DWORD end = 0;
		pLine->get_lineNumberEnd( &end );

		printf("%S<line_number source_file=\"%ws\" start=\"%d\" end=\"%d\" addr=\"0x%x\" /> \n",
					indent(12).c_str(), sourceFileName.GetBSTR(), start, end, addr);
	}
}

void iterateFunctions(PDBApiContext& ctx) {
	DWORD celt = 0;
	CComPtr<IDiaEnumSymbols> pEnum;
	CComPtr<IDiaSymbol> pSymbol;
	ctx.Global().findChildren(SymTagFunction, NULL, nsNone, &pEnum);
	if (pEnum == NULL) {
		return;
	}
	printf("%S<functions>\n", indent(4).c_str());
	while ( 1 ) {
		if (pEnum->Next( 1, &pSymbol, &celt ) != S_OK ) {
			break;
		}
		if (celt != 1) {
			break;
		}

		const DWORD tag = getTag(*pSymbol);
		if (tag != SymTagFunction) {//do not delete
			pSymbol = 0;
			continue;
		}

		const DWORD address = getRVA(*pSymbol);

		printf("%S<function name=\"%S\" address=\"0x%x\" length=\"0x%I64x\">\n", indent(8).c_str(), findMangledName(ctx, *pSymbol).c_str(), address, getLength(*pSymbol));

		dumpFunctionStackVariables(pSymbol, ctx.Session());
		dumpFunctionLines(*pSymbol, ctx.Session());

		printf("%S</function>\n", indent(8).c_str());

		pSymbol = 0;
	}
	printf("%S</functions>\n", indent(4).c_str());
}

void iterateSymbolTable(IDiaEnumSymbols * pSymbols) {
	DWORD celt = 0;
	while ( 1 ) {
		CComPtr<IDiaSymbol> pSymbol;
		if (pSymbols->Next( 1, &pSymbol, &celt ) != S_OK ) {
			break;
		}
		if (celt != 1) {
			break;
		}

		const std::wstring name = getName(*pSymbol);
		if (name.empty()) {
			continue;
		}
		printf("%S",                    indent(12).c_str());
		printf("<symbol name=\"%S\" ",  name.c_str());
		printf("address=\"0x%x\" ",     getRVA(*pSymbol));
		printf("length=\"0x%I64x\" ",   getLength(*pSymbol));
		printf("tag=\"%S\" ",           getTagAsString(*pSymbol).c_str());
		printf("kind=\"%S\" ",          getKindAsString(*pSymbol).c_str());
		printf("index=\"0x%x\" ",       getIndex(*pSymbol));
		printf("undecorated=\"%S\" ",   getUndecoratedName(*pSymbol).c_str());
		printf("value=\"%S\" ",         getValue(*pSymbol).c_str());
		printf("datatype=\"%S\" ",      getTypeAsString(*pSymbol).c_str());
		printf(" />\n");
	}
}

void iterateSourceFiles(IDiaEnumSourceFiles * pSourceFiles) {
	DWORD celt = 0;
	CComPtr<IDiaSourceFile> pSourceFile;
	while ( pSourceFiles->Next( 1, &pSourceFile, &celt ) == S_OK && celt == 1 ) {
		bstr_t name;
		DWORD id = 0;
		if( (pSourceFile->get_fileName( name.GetAddress() ) == S_OK) && (pSourceFile->get_uniqueId( &id ) == S_OK) ) {
			printf("%S<source_file name=\"%ws\" id=\"0x%x\" /> \n", indent(12).c_str(), name.GetBSTR(), id);
		}
		pSourceFile = NULL;
	}
}

/*
 * Maps data from the section number to segments of 
 * address space. Because DIA performs translations 
 * from the section offset to relative virtual addresses, 
 * most applications will not make use of the 
 * information in the segment map.
 */
void iterateSegments(IDiaEnumSegments * pSegments) {
	DWORD celt = 0;
	CComPtr<IDiaSegment> pSegment;
	while ( pSegments->Next( 1, &pSegment, &celt ) == S_OK && celt == 1 ) {
		DWORD rva = 0;
		DWORD seg = 0;
		pSegment->get_addressSection( &seg );
		pSegment->get_relativeVirtualAddress( &rva );
		printf("%S<segment number=\"%i\" address=\"0x%x\" />  \n", indent(12).c_str(), seg, rva);
		pSegment = NULL;
	}
}

/*
 * Retrieves data describing a section contribution, 
 * that is, a contiguous block of memory contributed 
 * to the image by a compiland.
 */
void iterateSections(PDBApiContext& ctx, IDiaEnumSectionContribs& secContribs) {
	DWORD celt = 0;

	while ( 1 ) {
		CComPtr<IDiaSectionContrib> pSecContrib;
		if (secContribs.Next( 1, &pSecContrib, &celt ) != S_OK ) {
			break;
		}
		if (celt != 1) {
			break;
		}

		CComPtr<IDiaSymbol> pSym;
		DWORD rva = 0;
		if (pSecContrib->get_relativeVirtualAddress( &rva ) == S_OK) {
			if (ctx.Session().findSymbolByRVA( rva, SymTagNull, &pSym ) != S_OK ) {
				pSym = NULL;
			}
		} 
		else {
			DWORD isect = 0;
			DWORD offset = 0;
			pSecContrib->get_addressSection( &isect );
			pSecContrib->get_addressOffset( &offset );
			pSecContrib = NULL;
			if (ctx.Session().findSymbolByAddr( isect, offset, SymTagNull, &pSym ) != S_OK ) {
				pSym = NULL;
			}
		}
		if (pSym == NULL) {
			printf("%S<section_contrib address=\"0x%x\" /> \n", indent(12).c_str(), rva);
		}
		else {
			std::wstring name = getName(*pSym);
			std::wstring tag  = getTagAsString(*pSym);

			printf("%S<section_contrib address=\"0x%x\" name=\"%S\" tag=\"%S\" /> \n", 
						indent(12).c_str(), rva, name.c_str(), tag.c_str());
		}
	}
}

/*
 * Accesses the program source code stored in the DIA data source.
 */
void iterateInjectedSource(IDiaEnumInjectedSources * pInjectedSrcs) {
	DWORD celt = 0;
	CComPtr<IDiaInjectedSource> pInjectedSrc;

	while ( 1 ) {
		if (pInjectedSrcs->Next( 1, &pInjectedSrc, &celt ) != S_OK ) {
			break;
		}
		if (celt != 1) {
			break;
		}

		bstr_t filename;
		pInjectedSrc->get_filename(filename.GetAddress());

		bstr_t objectname;
		pInjectedSrc->get_objectFilename(objectname.GetAddress());

		DWORD crc;
		pInjectedSrc->get_crc(&crc);

		ULONGLONG length;
		pInjectedSrc->get_length(&length);

		printf("%S<injected_source filename=\"%ws\" objectname=\"%ws\" crc=\"0x%x\" length=\"0x%I64x\" />\n",
					indent(8).c_str(),
					filename.GetBSTR(),
					objectname.GetBSTR(),
					crc,
					length);

		pInjectedSrc = NULL;
	}
}

/*
 * Exposes the details of a stack frame for execution points 
 * within the address range indicated by the 
 * address and block length.
 */
void iterateFrameData(IDiaEnumFrameData * pEnumFrameData) {
	DWORD celt = 0;

	while ( 1 ) {
		CComPtr<IDiaFrameData> pFrameData;
		if (pEnumFrameData->Next( 1, &pFrameData, &celt ) != S_OK) {
			break;
		}
		if (celt != 1) {
			break;
		}
		//TODO
	}
}

void iterateTables(PDBApiContext& ctx, bool printAll) {
	printf("%S<tables>\n", indent(4).c_str());
	DWORD celt = 0;

	CComPtr<IDiaEnumTables> pTables;

	if ( ctx.Session().getEnumTables( &pTables ) != S_OK ) {
		return;
	}

	while ( 1 ) {
		CComPtr<IDiaTable> pTable;
		if (pTables->Next( 1, &pTable, &celt ) != S_OK ) {
			break;
		}
		if (celt != 1) {
			break;
		}

		bstr_t name;
		pTable->get_name( name.GetAddress() );

		printf("%S<table name=\"%ws\">\n", indent(8).c_str(), name.GetBSTR() );

		CComPtr<IDiaEnumSymbols>          pSymbols;
		CComPtr<IDiaEnumSourceFiles>      pSourceFiles;
		CComPtr<IDiaEnumSegments>         pSegments;
		CComPtr<IDiaEnumSectionContribs>  pSecContribs;
		CComPtr<IDiaEnumInjectedSources>  pInjectedSrcs;
		CComPtr<IDiaEnumFrameData>        pEnumFrameData;

		if ( pTable->QueryInterface(IID_PPV_ARGS(&pSymbols) ) == S_OK ) {
			iterateSymbolTable(pSymbols);
		} 
		else if ( pTable->QueryInterface(IID_PPV_ARGS(&pSourceFiles) ) == S_OK ) {
			iterateSourceFiles(pSourceFiles);
		} 
		else if ( pTable->QueryInterface(IID_PPV_ARGS(&pSegments)) == S_OK ) {
			iterateSegments(pSegments);
		} 
		else if ( pTable->QueryInterface(IID_PPV_ARGS(&pSecContribs) ) == S_OK ) {
			if (printAll) {		
				iterateSections(ctx, *pSecContribs);
			}
		}
		else if ( pTable->QueryInterface(IID_PPV_ARGS(&pInjectedSrcs) ) == S_OK ) {
			iterateInjectedSource(pInjectedSrcs);
		}
		else if ( pTable->QueryInterface(IID_PPV_ARGS(&pEnumFrameData) ) == S_OK ) {
			iterateFrameData(pEnumFrameData);
		}

		printf("%S</table>\n", indent(8).c_str());
	}
	printf("%S</tables>\n", indent(4).c_str());
}
