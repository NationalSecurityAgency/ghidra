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
#include "err.h"

void warning( const char * msg )
{
	fprintf( stderr, "WARNING:\n" );
	fprintf( stderr, msg );
	fprintf( stderr, "\n" );
	exit( -1 );
}

void fatal( const char * msg )
{
	fprintf( stderr, "ERROR: %s\n", msg );
	exit( -1 );
}

void checkErr(HRESULT hResult) {
	if (hResult == S_OK) {
		return;
	}
	switch (hResult) {
		case E_PDB_NOT_FOUND:
			fatal("Failed to open the PDB file, or the PDB file has an invalid format.\n");
			break;
		case E_PDB_FORMAT:
			fatal("Attempted to access a PDB file with an obsolete format.\n");
			break;
		case E_PDB_INVALID_SIG:
			warning("PDB signature does not match.\n");
			break;
		case E_PDB_INVALID_AGE:
			warning("PDB age does not match.\n");
			break;
		case E_INVALIDARG:
			fatal("Invalid PDB file pointer.\n");
			break;
		case E_PDB_OUT_OF_MEMORY:
			fatal("Out of memory.\n");
			break;
		case E_PDB_CORRUPT:
			fatal("PDB files appears to be corrupt.\n");
			break;
		case E_PDB_INVALID_EXE_TIMESTAMP:
			fatal("Invalid timestamp in executable.\n");
			break;
		case E_UNEXPECTED:
			fatal("The data source has already been prepared.\n");
			break;
	}
	fatal("Unable to load data from PDB\n");
}
