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
// Queries a PDB in PdbQuery package for data and item type records that contain the search string.
//
//@category PDB

import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import pdbquery.PdbFactory;
import pdbquery.PdbFactory.PdbInfo;
import pdbquery.PdbQuery;

public class PdbQueryDatatypeScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		List<PdbInfo> orderedPdbInfo = PdbFactory.getPdbInfo();
		if (orderedPdbInfo.isEmpty()) {
			println("There are no open PDBs.  Run " + PdbQueryOpenScript.class.getSimpleName() +
				" to open a PDB.");
			return;
		}
		PdbInfo lastPdbInfo = PdbFactory.getLastPdbInfoByScriptClass(getClass());
		PdbInfo choice = askChoice("Choose PDB to query", "PDB Info", orderedPdbInfo, lastPdbInfo);

		AbstractPdb pdb = choice.getPdb();

		String searchString = askString("Enter Search String", "String");
		println("Searching " + choice.getFilename() + " for: " + searchString);

		PdbQuery.searchDataTypes(this, pdb, searchString);
		PdbQuery.searchItemTypes(this, pdb, searchString);
	}

}
