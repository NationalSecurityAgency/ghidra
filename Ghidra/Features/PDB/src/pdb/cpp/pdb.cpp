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

IDiaSession     * pSession;//Provides a query context for debug symbols
IDiaSymbol      * pGlobal;
IDiaDataSource  * pSource;

wchar_t * szLookup = NULL;

void dispose() {
	CoUninitialize();
	pSource  = 0;
	pSession = 0;
	pGlobal  = 0;
	printf("</pdb>\n");
}

int init(const char * szFilename, const char * szSignature, const char * szAge) {

	if ( CoInitialize(NULL) < 0) {
		fatal("Unable to initialize\n");
	}

	HRESULT hr = CoCreateInstance(_uuidof( DiaSource ), 
									NULL, 
									CLSCTX_INPROC_SERVER, 
									_uuidof( IDiaDataSource ), 
									(void **) &pSource);
	if (hr < 0) {
		switch (hr) {
			case REGDB_E_CLASSNOTREG:
				fatal("Unable to locate the DIA SDK. It is required to load PDB files.\n" \
					  "* See docs/README_PDB.html for DLL registration instructions.\n");
				break;
			default:
				char msg[256];
				sprintf(msg, "Unspecified error occurred: 0x%x\n", hr);
				fatal(msg);
				break;
		}
	}

	wchar_t wszFilename[ _MAX_PATH ];
	mbstowcs( wszFilename, szFilename, sizeof( wszFilename ) );

	if (szSignature == NULL && szAge == NULL) {
		hr = pSource->loadDataFromPdb( wszFilename );
	}
	else if (szSignature != NULL && szAge != NULL) {
		GUID guid;
		int isValidGUID = atog(&guid, szSignature);

		DWORD age = strtol(szAge, NULL, 16);

		if (isValidGUID == 0) {// .NET or later PDB file
			hr = pSource->loadAndValidateDataFromPdb( wszFilename, &guid, 0, age );
		}
		else {
			DWORD signature = strtol(szSignature, NULL, 16);
			hr = pSource->loadAndValidateDataFromPdb( wszFilename, NULL, signature, age );
		}
	}
	else {
		fatal("Invalid combination of GUID/Signature/Age parameters specified!");
	}
	checkErr(hr);

	if (pSource->openSession( &pSession ) < 0) {
		fatal("Unable to open session\n");
	}
	if (pSession->get_globalScope( &pGlobal ) < 0) {
		fatal("Unable to get global scope\n");
	}

	DWORD id = 0;
	pGlobal->get_symIndexId( &id );
	if ( id == 0 ) {
		fatal("Unable to get global symbol index\n");
	}

	BSTR exename = getName(pGlobal);
	
	GUID currGUID;
	BSTR guidString;

	DWORD currAge;

	// Include PDB GUID and age in XML output for compatibility checking
	if (pGlobal->get_guid( &currGUID ) == S_OK) {
		size_t maxGUIDStrLen = 64;
		wchar_t * guidStr = (wchar_t *)calloc(maxGUIDStrLen, sizeof(wchar_t));
		StringFromGUID2(currGUID, guidStr, maxGUIDStrLen);
		guidString = guidStr;

		if (pGlobal->get_age( &currAge ) == S_OK) {
			// don't do anything?
		} else {
			fatal("Unable to get PDB age\n");
		}
	} else {
		fatal("Unable to get GUID\n");
	}

	printf("<pdb file=\"%s\" exe=\"%ws\" guid=\"%ws\" age=\"%ld\">\n", szFilename, exename, guidString, currAge);

	return hr;
}


