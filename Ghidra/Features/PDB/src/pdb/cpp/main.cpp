/* ###
 * IP: GHIDRA
 * NOTE: Added additional options for output.
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
#include "iterate.h"
#include <signal.h>


void segvHandler(int sig) {
	exit(1);	// Just die - prevents OS from popping-up a dialog
}

int main(int argc, char ** argv) {
	if ( (argc < 2) || (argc > 5) ) {
		printf("USAGE:\n");
		printf("\tValidation:    %s <input pdb file> <guid OR signature> <age> [-fulloutput]\n", argv[0]);
		printf("\tNo Validation: %s <input pdb file> [-fulloutput]\n", argv[0]);
		printf("\nThe -fulloutput parameter must be specified in order for 'Sections' information to be output in the XML file.\n"); 
		exit(-1);
	}

	signal(SIGSEGV, &segvHandler);  // Exit on SEGV errors

	// Do not print all, by default
	// This workaround has been implemented since there appears to be some problem with the call to "findSymbolByRVA", which
	// slows down PDB processing immensely.
	// We do not use the "Sections" information during Ghidra processing.
	bool doPrintAll = false;

	if (argc <= 3) { // argc is either 2 or 3
		if ( (argc == 3) && (strcmp(argv[2], "-fulloutput") == 0) ) {
			doPrintAll = true;
		}
		init(argv[1], NULL, NULL);
	} else { // argc is either 4 or 5
		if ( (argc == 5) && (strcmp(argv[4], "-fulloutput") == 0) ) {
			doPrintAll = true;
		}
		init(argv[1], argv[2], argv[3]);
	}

	iterateEnums();
	iterateDataTypes();
	iterateTypedefs();
	iterateClasses();
	iterateFunctions();
	iterateTables(doPrintAll);

	dispose();
	return 0;
}
