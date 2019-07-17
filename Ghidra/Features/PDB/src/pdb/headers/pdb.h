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
#ifndef __PDB__PDB__H__
#define __PDB__PDB__H__

#include <string>
#include <stdio.h>
#include <assert.h>
#include <atlcomcli.h>
#include "dia2.h"
#include "diacreate.h"
#include "cvconst.h"
#include "err.h"

class AutoCoInit
{
public:
	AutoCoInit()
	{
		hr = ::CoInitialize(NULL);
	}

	~AutoCoInit()
	{
		if (SUCCEEDED(hr))
		{
			::CoUninitialize();
		}
	}

	HRESULT Result() const { return hr; }

private:
	HRESULT hr = E_FAIL;
};

class PDBApiContext
{
public:
	PDBApiContext(const std::wstring& szFilename, const std::wstring& szSignature, const std::wstring& szAge);
	~PDBApiContext();

	IDiaSession& Session() const { return *pSession; }
	IDiaSymbol& Global() const { return *pGlobal; }
private:
	void dispose();
	int init(const std::wstring& szFilename, const std::wstring& szSignature, const std::wstring& szAge);

private:
	AutoCoInit mCoInit;
	CComPtr<IDiaSession>      pSession;//Provides a query context for debug symbols
	CComPtr<IDiaSymbol>       pGlobal;
	CComPtr<IDiaDataSource>   pSource;
};

#endif
