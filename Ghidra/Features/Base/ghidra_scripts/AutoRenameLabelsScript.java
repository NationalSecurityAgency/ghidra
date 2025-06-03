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
//Renames default labels in a selected region, using
//a user-defined stub and a one-up naming convention.
//@category Symbol

import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

public class AutoRenameLabelsScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentSelection == null || currentSelection.isEmpty()) {
			println("No selection exists.");
			return;
		}

		String baseName = askString("Auto Rename Labels", "Enter label name prefix:");
		if (baseName == null) {
			return;
		}

		int num = 1;
		AddressSetView view = currentSelection;
		if ((view == null) || (view.isEmpty())) {
			return;
		}

		SymbolTable symbolTable = currentProgram.getSymbolTable();
		AddressIterator it = view.getAddresses(true);
		CompoundCmd<Program> cmd = new CompoundCmd<>("Auto Rename Labels");
		while (it.hasNext()) {
			Address address = it.next();
			Symbol primary = symbolTable.getPrimarySymbol(address);
			if (primary != null && primary.getSource() == SourceType.DEFAULT) {
				cmd.add(new RenameLabelCmd(primary, baseName + num++, SourceType.USER_DEFINED));
			}
		}
		if (cmd.size() > 0) {
			if (!cmd.applyTo(currentProgram)) {
				String msg = cmd.getStatusMsg();
				if (msg != null && msg.length() > 0) {
					setToolStatusMessage(msg, true);
				}
			}
		}
		else {
			println("No default labels found in selection.");
		}
	}
}
