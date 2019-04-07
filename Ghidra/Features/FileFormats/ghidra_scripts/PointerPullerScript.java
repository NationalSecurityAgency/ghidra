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
//Pulls symbol name through pointer references.
//@category Mac OS X

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class PointerPullerScript extends GhidraScript {
	private final static String stringPrefix = "s_";

	@Override
	public void run() throws Exception {
		Listing listing = currentProgram.getListing();
		DataIterator dataIterator = listing.getDefinedData(true);
		while (dataIterator.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			Data data = dataIterator.next();
			process(data);
		}
	}

	private void process(Data data) throws DuplicateNameException, InvalidInputException {
		if (monitor.isCancelled()) {
			return;
		}
		if (data == null) {
			return;
		}
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		if (data.isPointer()) {
			monitor.setMessage("Pulling pointer at " + data.getMinAddress());
			Symbol dataSymbol = getSymbolAt(data.getMinAddress());

			//does this symbol already have a real name?
			if (dataSymbol != null && !dataSymbol.isDynamic()) {
				return;
			}

			Address destinationAddress = data.getAddress(0);
			Symbol destinationSymbol = getSymbolAt(destinationAddress);
			if (destinationSymbol == null) {

				//is it a multi-level pointer ( e.g., pointer->pointer->data )?
				//process destination, the re-process data
				Data destinationData = getDataAt(destinationAddress);
				if (destinationData.isPointer()) {
					process(destinationData);
					process(data);
				}
				return;
			}
			String destinationSymbolName = destinationSymbol.getName();
			if (SymbolUtilities.startsWithDefaultDynamicPrefix(destinationSymbolName)) {
				return;
			}
			if (destinationSymbol.isDynamic() && !destinationSymbolName.startsWith(stringPrefix)) {
				return;
			}
			if (destinationSymbol.isDynamic() && destinationSymbolName.startsWith(stringPrefix)) {
				int indexOf = destinationSymbolName.indexOf(destinationAddress.toString());
				destinationSymbolName = destinationSymbolName.substring(0, indexOf - 1);
			}
			Namespace nameSpace = getNameSpaceForData(data);
			symbolTable.createLabel(data.getMinAddress(), destinationSymbolName, nameSpace,
				SourceType.ANALYSIS);

		}
	}

	private Namespace getNameSpaceForData(Data data)
			throws DuplicateNameException, InvalidInputException {
		String nameSpaceName = "PulledPointers";
		MemoryBlock memoryBlock = getMemoryBlock(data.getMinAddress());
		if (memoryBlock != null) {
			nameSpaceName = memoryBlock.getName();
		}
		Namespace nameSpace = getNamespace(null, nameSpaceName);
		if (nameSpace == null) {
			nameSpace = currentProgram.getSymbolTable().createNameSpace(null, nameSpaceName,
				SourceType.ANALYSIS);
		}
		return nameSpace;
	}

}
