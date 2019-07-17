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
//This script applies a meaningful label (based on data type and data representation) on all referenced data that does
// not already have a meaningful name (ie strings), and pointers
// This script only makes labels where there currently is a default label or an analysis label. It does not overwrite user or imported labels.
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;

public class LabelDataScript extends GhidraScript {

	Listing listing;
	Memory memory;
	SymbolTable symbolTable;

	@Override
	public void run() throws Exception {
		listing = currentProgram.getListing();
		memory = currentProgram.getMemory();
		symbolTable = currentProgram.getSymbolTable();

		monitor.setMessage("Labeling referenced data...");
		Data data = getFirstData();
		while ((data != null) && (!monitor.isCancelled())) {
			if (!data.isPointer() &&
				(!data.getBaseDataType().getName().toLowerCase().contains("string")) &&
				(!data.getBaseDataType().getName().toLowerCase().contains("unicode"))) {
				Symbol sym = symbolTable.getPrimarySymbol(data.getMinAddress());
				if ((sym != null) && ((sym.getSource() == SourceType.DEFAULT) ||
					(sym.getSource() == SourceType.ANALYSIS))) {
					String newLabel =
						data.getDefaultLabelPrefix(null) + "_" +
							SymbolUtilities.replaceInvalidChars(
								data.getDefaultValueRepresentation(), false) +
							"_" + data.getMinAddress().toString();
					Symbol newSym = symbolTable.createLabel(data.getMinAddress(), newLabel,
						SourceType.ANALYSIS);
					println(data.getMinAddress().toString() + " " + newLabel);
					if (!newSym.isPrimary()) {
						newSym.setPrimary();
					}

				}
			}
			data = getDataAfter(data);
		}
	}
}
