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
#include <stdlib.h>

PDBApiContext::PDBApiContext(const std::wstring& szFilename, const std::wstring& szSignature, const std::wstring& szAge)
{
	if (FAILED(mCoInit.Result())) {
		fatal("Unable to initialize\n");
	}
	init(szFilename, szSignature, szAge);
}

PDBApiContext::~PDBApiContext()
{
	dispose();
}

void PDBApiContext::dispose() {
	printf("</pdb>\n");
}

int PDBApiContext::init(const std::wstring& szFilename, const std::wstring& szSignature, const std::wstring& szAge) {

	HRESULT hr = CoCreateInstance(_uuidof( DiaSource ), 
									NULL, 
									CLSCTX_INPROC_SERVER, 
									IID_PPV_ARGS(&pSource));
	if (FAILED(hr)) {
		switch (hr) {
			case REGDB_E_CLASSNOTREG:
				fatal("Unable to locate the DIA SDK. It is required to load PDB files.\n" \
					  "* See docs/README_PDB.html for DLL registration instructions.\n");
				break;
			default:
				char msg[256] = {};
				sprintf_s(msg, "Unspecified error occurred: 0x%lx\n", hr);
				fatal(msg);
				break;
		}
	}

	if (szSignature.empty() && szAge.empty()) {
		hr = pSource->loadDataFromPdb(szFilename.c_str() );
	}
	else if (!szSignature.empty() && !szAge.empty()) {
		GUID guid = {};
		std::wstring bracedGuidString = L"{" + szSignature + L"}";;
		const HRESULT guidConv = CLSIDFromString(bracedGuidString.c_str(), &guid);

		const DWORD age = wcstol(szAge.c_str(), NULL, 16);

		if (SUCCEEDED(guidConv)) {// .NET or later PDB file
			hr = pSource->loadAndValidateDataFromPdb(szFilename.c_str(), &guid, 0, age );
		}
		else {
			const DWORD signature = wcstol(szSignature.c_str(), NULL, 16);
			hr = pSource->loadAndValidateDataFromPdb(szFilename.c_str(), NULL, signature, age );
		}
	}
	else {
		fatal("Invalid combination of GUID/Signature/Age parameters specified!");
	}
	checkErr(hr);

	if (pSource->openSession( &pSession ) != S_OK) {
		fatal("Unable to open session\n");
	}
	if (pSession->get_globalScope( &pGlobal ) != S_OK) {
		fatal("Unable to get global scope\n");
	}

	DWORD id = 0;
	pGlobal->get_symIndexId( &id );
	if ( id == 0 ) {
		fatal("Unable to get global symbol index\n");
	}

	const std::wstring exename = getName(*pGlobal);

	// Include PDB GUID and age in XML output for compatibility checking
	GUID currGUID = {};
	DWORD currAge = 0;
	int maxGUIDStrLen = 64;
	std::wstring guidStr(maxGUIDStrLen, L'\0');

	if (pGlobal->get_guid( &currGUID ) == S_OK) {
		if (StringFromGUID2(currGUID, &guidStr[0], maxGUIDStrLen) <= 0) {
			fatal("Unable to convert GUID\n");
		}

		if (pGlobal->get_age( &currAge ) != S_OK) {
			fatal("Unable to get PDB age\n");
		}
	} else {
		fatal("Unable to get GUID\n");
	}

	printf("<pdb file=\"%S\" exe=\"%S\" guid=\"%S\" age=\"%ld\">\n", szFilename.c_str(), exename.c_str(), guidStr.c_str(), currAge);

	return hr;
}


