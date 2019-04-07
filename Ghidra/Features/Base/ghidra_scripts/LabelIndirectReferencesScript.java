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
//This script searches for references to data with user labels.
//When a reference is found a new "ptr_labelname" is applied
//Check the console for a list of references that have been added.
//@category Analysis
import java.util.*;

import ghidra.app.plugin.core.analysis.ReferenceAddressPair;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class LabelIndirectReferencesScript extends GhidraScript {

	Listing listing;
	Memory memory;
	SymbolTable symbolTable;

	@Override
	public void run() throws Exception {
		listing = currentProgram.getListing();
		memory = currentProgram.getMemory();
		symbolTable = currentProgram.getSymbolTable();

		monitor.setMessage("Labeling indirect references...");

		List<Address> dataAddrSet = new ArrayList<Address>();

		// Iterate through all defined strings and save their addresses
		DataIterator dataIterator = listing.getDefinedData(true);
		while (dataIterator.hasNext() && !monitor.isCancelled()) {
			Data nextData = dataIterator.next();
			Address addr = nextData.getMinAddress();
			Symbol sym = getSymbolAt(addr);

			if ((sym != null) && (sym.getSource() == SourceType.USER_DEFINED)) {
				// Save
				dataAddrSet.add(nextData.getMinAddress());
			}
		}

		// Check that data with user symbols are found
		if (dataAddrSet.size() == 0) {
			popup("No data with user symbols were found.");
			return;
		}

		println("Number of data items with user symbols found: " + dataAddrSet.size());

		for (int i = 0; i < dataAddrSet.size(); i++) {
			Address dataAddr = dataAddrSet.get(i);

			List<Address> allRefAddrs = new ArrayList<Address>();
			allRefAddrs = findAllReferences(dataAddr, monitor);
			if (allRefAddrs == null) {
				println("User cancelled script");
				return;
			}

			// Loop through refs to see which that have references to them (ie a label there)
			for (int j = 0; j < allRefAddrs.size(); j++) {
				Address refFromAddr = allRefAddrs.get(j);
				if (listing.getInstructionContaining(refFromAddr) == null) {
					// if the reference to the data is not inside an instruction Code Unit get the references to the data references
					Reference[] refRef = getReferencesTo(refFromAddr);
					// if there are references to the ptr_dataAddr then put a ptr_data label on it
					if (refRef.length > 0) {
						String newLabel = "ptr_" + listing.getDataAt(dataAddr).getLabel() + "_" +
							allRefAddrs.get(j);
						println(newLabel);
						symbolTable.createLabel(allRefAddrs.get(j), newLabel, SourceType.ANALYSIS);
					}
				}
			}
		}
	}

	public List<Address> findAllReferences(Address addr, TaskMonitor taskMonitor) {

		List<ReferenceAddressPair> directReferenceList = new ArrayList<ReferenceAddressPair>();
		List<Address> results = new ArrayList<Address>();
		Address toAddr = currentProgram.getListing().getCodeUnitContaining(addr).getMinAddress();

		try {
			ProgramMemoryUtil.loadDirectReferenceList(currentProgram, 1, toAddr, currentSelection,
				directReferenceList, taskMonitor);
		}
		catch (CancelledException e) {
			return Collections.emptyList();
		}

		for (ReferenceAddressPair rap : directReferenceList) {
			if (taskMonitor.isCancelled()) {
				return null;
			}
			Address fromAddr =
				currentProgram.getListing().getCodeUnitContaining(rap.getSource()).getMinAddress();
			if (!results.contains(fromAddr)) {
				results.add(fromAddr);
			}
		}

		ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(toAddr);
		while (ri.hasNext()) {
			Reference r = ri.next();
			Address fromAddr = r.getFromAddress();
			if (!results.contains(fromAddr)) {
				results.add(fromAddr);
			}
		}
		return results;
	}
}
