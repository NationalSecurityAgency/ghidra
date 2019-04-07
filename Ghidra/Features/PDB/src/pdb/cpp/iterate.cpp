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

void iterateEnumMembers(IDiaSymbol * pSymbol) {
	DWORD celt;
	IDiaEnumSymbols * pEnum;
	IDiaSymbol * pMember;
	pSymbol->findChildren(SymTagNull, NULL, nsNone, &pEnum);
	if (pEnum == NULL) {
		return;
	}
	while (1) {
		if (pEnum->Next( 1, &pMember, &celt ) < 0) {
			break;
		}
		if (celt != 1) {
			break;
		}
		BSTR name = getName(pMember);
		BSTR value = getValue(pMember);
		printf("%s<member name=\"%ws\" value=\"%ws\" />\n", indent(12), name, value);
		pMember = 0;
	}
}

void iterateEnums() {
	DWORD celt;
	IDiaEnumSymbols * pEnum;
	IDiaSymbol * pSymbol;
	pGlobal->findChildren(SymTagEnum, NULL, nsNone, &pEnum);
	if (pEnum == NULL) {
		return;
	}
	printf("%s<enums>\n", indent(4));
	while ( 1 ) {
		if (pEnum->Next( 1, &pSymbol, &celt ) < 0) {
			break;
		}
		if (celt != 1) {
			break;
		}

		DWORD tag = getTag(pSymbol);
		if (tag != SymTagEnum) {//do not delete
			continue;
		}

		BSTR      name = getName(pSymbol);
		BSTR      type = getTypeAsString(pSymbol);
		ULONGLONG len  = getLength(pSymbol);

		printf("%s<enum name=\"%ws\" type=\"%ws\" length=\"0x%x\" >\n", indent(8), name, type, len);

		iterateEnumMembers(pSymbol);

		printf("%s</enum>\n", indent(8));
		pSymbol = 0;
	}
	printf("%s</enums>\n", indent(4));
}

void iterateMembers(IDiaSymbol * pSymbol) {
	DWORD celt;
	IDiaEnumSymbols * pEnum;
	IDiaSymbol * pMember;
	pSymbol->findChildren(SymTagNull, NULL, nsNone, &pEnum);
	if (pEnum == NULL) {
		return;
	}
	while (1) {
		if (pEnum->Next( 1, &pMember, &celt ) < 0) {
			break;
		}
		if (celt != 1) {
			break;
		}
		printf("%s<member name=\"%ws\" datatype=\"%ws\" offset=\"0x%x\" kind=\"%ws\" length=\"0x%x\" />\n", 
					indent(12), 
					getName(pMember), 
					getTypeAsString(pMember),
					getOffset(pMember),
					getKindAsString(pMember),
					getLength(pMember));
	}
}

void iterateDataTypes() {
	DWORD celt;
	IDiaEnumSymbols * pEnum;
	IDiaSymbol * pSymbol;
	pGlobal->findChildren(SymTagUDT, NULL, nsNone/*nsfCaseInsensitive|nsfUndecoratedName*/, &pEnum);
	if (pEnum == NULL) {
		return;
	}
	printf("%s<datatypes>\n", indent(4));
	while ( 1 ) {
		if (pEnum->Next( 1, &pSymbol, &celt ) < 0) {
			break;
		}
		if (celt != 1) {
			break;
		}

		DWORD tag = getTag(pSymbol);
		if (tag != SymTagUDT) {//do not delete
			continue;
		}

		if (getUdtKind(pSymbol) == UdtClass) {
			continue;
		}

		BSTR      name = getName(pSymbol);
		BSTR      kind = getKindAsString(pSymbol);
		ULONGLONG len  = getLength(pSymbol);

		if ( len == 0 ) {
			continue;
		}

		printf("%s<datatype name=\"%ws\" kind=\"%ws\" length=\"0x%x\" >\n", indent(8), name, kind, len);

		iterateMembers(pSymbol);

		printf("%s</datatype>\n", indent(8));
		pSymbol = 0;
	}
	printf("%s</datatypes>\n", indent(4));
}

void iterateTypedefs() {
	DWORD celt;
	IDiaEnumSymbols * pEnum;
	IDiaSymbol * pSymbol;
	pGlobal->findChildren(SymTagTypedef, NULL, nsNone/*nsfCaseInsensitive|nsfUndecoratedName*/, &pEnum);
	if (pEnum == NULL) {
		return;
	}
	printf("%s<typedefs>\n", indent(4));
	while ( 1 ) {
		if (pEnum->Next( 1, &pSymbol, &celt ) < 0) {
			break;
		}
		if (celt != 1) {
			break;
		}

		DWORD tag = getTag(pSymbol);
		if (tag != SymTagTypedef) {//do not delete
			continue;
		}
		BSTR name = getName(pSymbol);
		BSTR type = getTypeAsString(pSymbol);

		printf("%s<typedef name=\"%ws\" basetype=\"%ws\" />\n", indent(8), name, type);

		pSymbol = 0;
	}
	printf("%s</typedefs>\n", indent(4));
}

void iterateClasses() {
	DWORD celt;
	IDiaEnumSymbols * pEnum;
	IDiaSymbol * pSymbol;
	pGlobal->findChildren(SymTagUDT, NULL, nsNone/*nsfCaseInsensitive|nsfUndecoratedName*/, &pEnum);
	if (pEnum == NULL) {
		return;
	}
	printf("%s<classes>\n", indent(4));
	while ( 1 ) {
		if (pEnum->Next( 1, &pSymbol, &celt ) < 0) {
			break;
		}
		if (celt != 1) {
			break;
		}

		DWORD tag = getTag(pSymbol);
		if (tag != SymTagUDT) {//do not delete
			continue;
		}

		if (getUdtKind(pSymbol) != UdtClass) {
			continue;
		}

		BSTR      name = getName(pSymbol);
		ULONGLONG len  = getLength(pSymbol);

		if ( len == 0 ) {
			continue;
		}

		printf("%s<class name=\"%ws\" length=\"0x%x\" >\n", indent(8), name, len);

		iterateMembers(pSymbol);

		printf("%s</class>\n", indent(8));
		pSymbol = 0;
	}
	printf("%s</classes>\n", indent(4));
}

void dumpFunctionStackVariables( DWORD rva )
{
	IDiaSymbol * pBlock;
	if ( FAILED( pSession->findSymbolByRVA( rva, SymTagBlock, &pBlock ) ) ) {
		fatal( "Failed to find symbols by RVA" );
	}
	for ( ; pBlock != NULL; ) {
		IDiaEnumSymbols * pEnum;
		// Local data search
		if ( FAILED( pBlock->findChildren( SymTagNull, NULL, nsNone, &pEnum ) ) ) {
			fatal( "Local scope findChildren failed" );
		}
		IDiaSymbol * pSymbol;
		DWORD tag;
		DWORD celt;
		while ( pEnum != NULL && SUCCEEDED( pEnum->Next( 1, &pSymbol, &celt ) ) && celt == 1 ) {
			pSymbol->get_symTag( &tag );
			if ( tag == SymTagData ) {
				printf("%s<stack_variable name=\"%ws\" kind=\"%ws\" offset=\"0x%x\" datatype=\"%ws\" length=\"0x%x\" />\n", 
							indent(12),
							getName(pSymbol), 
							getKindAsString(pSymbol), 
							getOffset(pSymbol),
							getTypeAsString(pSymbol),
							getLength(pSymbol));
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
				while ( pValues != NULL && SUCCEEDED( pValues->Next( 1, &pSymbol, &celt ) ) && celt == 1 ) {
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
		IDiaSymbol * pParent;
		if ( SUCCEEDED( pBlock->get_lexicalParent( &pParent ) ) && pParent != NULL ) {
			pBlock = pParent;
		} 
		else {
			//fatal( "Finding lexical parent failed." );
		}
	};
}

void dumpFunctionLines( IDiaSymbol* pSymbol, IDiaSession* pSession )
{
	ULONGLONG length = 0;
	DWORD isect = 0;
	DWORD offset = 0;
	pSymbol->get_addressSection( &isect );
	pSymbol->get_addressOffset( &offset );
	pSymbol->get_length( &length );
	if ( isect == 0 || length <= 0 ) {
		return;
	}
	IDiaEnumLineNumbers * pLines;
	if (pSession->findLinesByAddr( isect, offset, static_cast<DWORD>( length ), &pLines ) < 0) {
		return;
	}
	IDiaLineNumber * pLine;
	DWORD celt;
	while ( 1 ) {
		if (pLines->Next( 1, &pLine, &celt ) < 0) {
			break;
		}
		if (celt != 1) {
			break;
		}

		IDiaSymbol * pComp;
		pLine->get_compiland( &pComp );

		IDiaSourceFile * pSrc;
		pLine->get_sourceFile( &pSrc );

		BSTR sourceFileName = NULL;
		pSrc->get_fileName( &sourceFileName );

		DWORD addr;
		pLine->get_relativeVirtualAddress( &addr );

		DWORD start;
		pLine->get_lineNumber( &start );
		DWORD end;
		pLine->get_lineNumberEnd( &end );

		printf("%s<line_number source_file=\"%ws\" start=\"0x%x\" end=\"0x%x\" addr=\"0x%x\" /> \n", 
					indent(12), sourceFileName, start, end, addr);

		pLine = NULL;
	}
}

void iterateFunctions() {
	DWORD celt;
	IDiaEnumSymbols * pEnum;
	IDiaSymbol * pSymbol;
	pGlobal->findChildren(SymTagFunction, NULL, nsNone, &pEnum);
	if (pEnum == NULL) {
		return;
	}
	printf("%s<functions>\n", indent(4));
	while ( 1 ) {
		if (pEnum->Next( 1, &pSymbol, &celt ) < 0) {
			break;
		}
		if (celt != 1) {
			break;
		}

		DWORD tag = getTag(pSymbol);
		if (tag != SymTagFunction) {//do not delete
			continue;
		}

		BSTR      name    = findMangledName(pSymbol);
		DWORD     address = getRVA(pSymbol);
		ULONGLONG len     = getLength(pSymbol);

		printf("%s<function name=\"%ws\" address=\"0x%x\" length=\"0x%x\">\n", indent(8), name, address, len);

		dumpFunctionStackVariables(address);
		dumpFunctionLines(pSymbol, pSession);

		printf("%s</function>\n", indent(8));

		pSymbol = 0;
	}
	printf("%s</functions>\n", indent(4));
}

void iterateSymbolTable(IDiaEnumSymbols * pSymbols) {
	DWORD celt;
	IDiaSymbol * pSymbol;

	while ( 1 ) {
		if (pSymbols->Next( 1, &pSymbol, &celt ) < 0) {
			break;
		}
		if (celt != 1) {
			break;
		}

		BSTR name = getName(pSymbol);
		if (name == NULL) {
			continue;
		}

		printf("%s",                    indent(12));
		printf("<symbol name=\"%ws\" ", name);
		printf("address=\"0x%x\" ",     getRVA(pSymbol));
		printf("length=\"0x%x\" ",      getLength(pSymbol));
		printf("tag=\"%ws\" ",          getTagAsString(pSymbol));
		printf("kind=\"%ws\" ",         getKindAsString(pSymbol));
		printf("index=\"0x%x\" ",       getIndex(pSymbol));
		printf("undecorated=\"%ws\" ",  getUndecoratedName(pSymbol));
		printf("value=\"%ws\" ",        getValue(pSymbol));
		printf("datatype=\"%ws\" ",     getTypeAsString(pSymbol));
		printf(" />\n");

		pSymbol = NULL;
	}
}

void iterateSourceFiles(IDiaEnumSourceFiles * pSourceFiles) {
	HRESULT hr;
	DWORD celt;
	IDiaSourceFile * pSourceFile;
	while ( SUCCEEDED( hr = pSourceFiles->Next( 1, &pSourceFile, &celt ) ) && celt == 1 ) {
		BSTR name;
		pSourceFile->get_fileName( &name );
		DWORD id;
		pSourceFile->get_uniqueId( &id );
		if ( name != NULL ) {
			printf("%s<source_file name=\"%ws\" id=\"0x%x\" /> \n", indent(12), name, id);
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
	HRESULT hr;
	DWORD celt;
	IDiaSegment * pSegment;
	while ( SUCCEEDED( hr = pSegments->Next( 1, &pSegment, &celt ) ) && celt == 1 ) {
		DWORD rva;
		DWORD seg;
		pSegment->get_addressSection( &seg );
		pSegment->get_relativeVirtualAddress( &rva );
		printf("%s<segment number=\"%i\" address=\"0x%x\" />  \n", indent(12), seg, rva);
		pSegment = NULL;
	}
}

/*
 * Retrieves data describing a section contribution, 
 * that is, a contiguous block of memory contributed 
 * to the image by a compiland.
 */
void iterateSections(IDiaEnumSectionContribs * pSecContribs) {
	DWORD celt;
	IDiaSymbol * pSym;
	IDiaSectionContrib * pSecContrib;

	while ( 1 ) {
		if (pSecContribs->Next( 1, &pSecContrib, &celt ) < 0 ) {
			break;
		}
		if (celt != 1) {
			break;
		}
		DWORD rva;
		if ( pSecContrib->get_relativeVirtualAddress( &rva ) == S_OK ) {
			if ( pSession->findSymbolByRVA( rva, SymTagNull, &pSym ) != S_OK ) {
				pSym = NULL;
			}
		} 
		else {
			DWORD isect;
			DWORD offset;
			pSecContrib->get_addressSection( &isect );
			pSecContrib->get_addressOffset( &offset );
			pSecContrib = NULL;
			IDiaSymbol * pSym;
			if ( pSession->findSymbolByAddr( isect, offset, SymTagNull, &pSym ) != S_OK ) {
				pSym = NULL;
			}         
		}
		if (pSym == NULL) {
			printf("%s<section_contrib address=\"0x%x\" /> \n", indent(12), rva);
		}
		else {
			BSTR  name = getName(pSym);
			BSTR  tag  = getTagAsString(pSym);

			printf("%s<section_contrib address=\"0x%x\" name=\"%ws\" tag=\"%ws\" /> \n", 
						indent(12), rva, name, tag);
		}
	}
}

/*
 * Accesses the program source code stored in the DIA data source.
 */
void iterateInjectedSource(IDiaEnumInjectedSources * pInjectedSrcs) {
	DWORD celt;
	IDiaInjectedSource* pInjectedSrc;

	while ( 1 ) {
		HRESULT hr = pInjectedSrcs->Next( 1, &pInjectedSrc, &celt );
		if (hr < 0) {
			break;
		}
		if (celt != 1) {
			break;
		}

		BSTR filename;
		pInjectedSrc->get_filename(&filename);

		BSTR objectname;
		pInjectedSrc->get_objectFilename(&objectname);

		DWORD crc;
		pInjectedSrc->get_crc(&crc);

		ULONGLONG length;
		pInjectedSrc->get_length(&length);

		printf("%s<injected_source filename=\"%ws\" objectname=\"%ws\" crc=\"0x%x\" length=\"0x%x\" />\n",
					indent(8),
					filename,
					objectname,
					crc,
					length);
	}
}

/*
 * Exposes the details of a stack frame for execution points 
 * within the address range indicated by the 
 * address and block length.
 */
void iterateFrameData(IDiaEnumFrameData * pEnumFrameData) {
	DWORD celt;
	IDiaFrameData * pFrameData;

	while ( 1 ) {
		HRESULT hr = pEnumFrameData->Next( 1, &pFrameData, &celt );
		if (hr < 0) {
			break;
		}
		if (celt != 1) {
			break;
		}
		//TODO
	}
}

int iterateTables(const bool printAll) {
	printf("%s<tables>\n", indent(4));
	HRESULT hr;
	DWORD celt;

	IDiaEnumTables * pTables;

	hr = pSession->getEnumTables( &pTables );
	if ( hr < 0) {
		return hr;
	}

	IDiaTable * pTable;

	while ( 1 ) {
		if (pTables->Next( 1, &pTable, &celt ) < 0) {
			break;
		}
		if (celt != 1) {
			break;
		}
		BSTR name;
		pTable->get_name( &name );

		printf("%s<table name=\"%ws\">\n", indent(8), name );

		IDiaEnumSymbols         * pSymbols;
		IDiaEnumSourceFiles     * pSourceFiles;
		IDiaEnumSegments        * pSegments;
		IDiaEnumSectionContribs * pSecContribs;
		IDiaEnumInjectedSources * pInjectedSrcs;
		IDiaEnumFrameData       * pEnumFrameData;

		if ( SUCCEEDED( pTable->QueryInterface( _uuidof( IDiaEnumSymbols ), (void**)&pSymbols ) ) ) {
			iterateSymbolTable(pSymbols);
		} 
		else if ( SUCCEEDED( pTable->QueryInterface( _uuidof( IDiaEnumSourceFiles ), (void**)&pSourceFiles ) ) ) {
			iterateSourceFiles(pSourceFiles);
		} 
		else if ( SUCCEEDED( pTable->QueryInterface( _uuidof( IDiaEnumSegments ), (void**)&pSegments ) ) ) {
			iterateSegments(pSegments);
		} 
		else if ( SUCCEEDED( pTable->QueryInterface( _uuidof( IDiaEnumSectionContribs ), (void**)&pSecContribs ) ) ) {
			if (printAll) {		
				iterateSections(pSecContribs);
			}
		}
		else if ( SUCCEEDED( pTable->QueryInterface( _uuidof( IDiaEnumInjectedSources ), (void**)&pInjectedSrcs ) ) ) {
			iterateInjectedSource(pInjectedSrcs);
		}
		else if ( SUCCEEDED( pTable->QueryInterface( _uuidof( IDiaEnumFrameData ), (void**)&pEnumFrameData ) ) ) {
			iterateFrameData(pEnumFrameData);
		}

		printf("%s</table>\n", indent(8));
		pTable = NULL;
	}
	printf("%s</tables>\n", indent(4));

	return 0;
}
