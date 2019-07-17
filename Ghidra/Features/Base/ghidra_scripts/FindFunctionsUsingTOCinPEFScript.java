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
//This script finds a .toc symbol, which is used to search for function pointers.
//@category Search

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.plugin.core.analysis.FindReferencesTableModel;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

public class FindFunctionsUsingTOCinPEFScript extends GhidraScript {

	private int addrSize = 4;
	Listing listing;
	SymbolTable symbolTable;

	@Override
	public void run() throws Exception {
		listing = currentProgram.getListing();
		symbolTable = currentProgram.getSymbolTable();

		// Find .toc symbol
		Symbol toc = SymbolUtilities.getExpectedLabelOrFunctionSymbol(currentProgram, ".toc",
			err -> Msg.error(this, err));
		if (toc == null) {
			return;
		}
		Address tocAddress = toc.getAddress();

		// Get direct refs to .toc
		monitor.setMessage("Finding references to .toc");
		FindReferencesTableModel refs =
			new FindReferencesTableModel(tocAddress, state.getTool(), currentProgram);
		while (refs.isBusy()) {
			if (monitor.isCancelled()) {
				break;
			}
		}

		// Loop through refs to find functions
		for (int i = 0; i < refs.getRowCount(); ++i) {
			monitor.setMessage("Finding functions");
			if (monitor.isCancelled()) {
				break;
			}

			// Make them pointers to .toc
			Address refAddr = refs.getAddress(i);
			listing.clearCodeUnits(refAddr, refAddr, false);
			listing.createData(refAddr, new PointerDataType());

			// Make previous code unit (addr-addrSize) a pointer
			Address codeAddr = refAddr.subtract(addrSize);
			listing.clearCodeUnits(codeAddr, codeAddr, false);
			CreateDataCmd cmd = new CreateDataCmd(codeAddr, new PointerDataType());
			cmd.applyTo(currentProgram);
// 	 		listing.createData(codeAddr, new PointerDataType());

			currentProgram.flushEvents();
		}

		popup("Script complete.\n\nNote:  Auto analyzer may still be running.\n" +
			"(Depending on the size of the binary, analysis may take a while...see Ghidra's progress bar.)");

	}
}
