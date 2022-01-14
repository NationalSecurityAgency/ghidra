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
// Closes a user-selected PDB that was opened in the PdbQuery package.
//
//@category PDB

import java.util.List;

import ghidra.app.script.GhidraScript;
import pdbquery.PdbFactory;
import pdbquery.PdbFactory.PdbInfo;

public class PdbQueryCloseScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		List<PdbInfo> orderedPdbInfo = PdbFactory.getPdbInfo();
		if (orderedPdbInfo.isEmpty()) {
			println("There are no open PDBs.  Run " + PdbQueryOpenScript.class.getSimpleName() +
				" to open a PDB.");
			return;
		}
		PdbInfo lastPdbInfo = PdbFactory.getLastPdbInfoByScriptClass(getClass());

		PdbInfo choice = askChoice("Choose PDB to Close", "PDB Info", orderedPdbInfo, lastPdbInfo);

		PdbFactory.closePdb(this, choice.getFilename());
	}
}
