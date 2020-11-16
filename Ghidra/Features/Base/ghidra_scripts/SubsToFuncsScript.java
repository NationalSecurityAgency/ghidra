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
//Converts subroutines to functions.
//Subroutines are located using the active
//subroutine model on the BlockModelService.
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.app.services.BlockModelService;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class SubsToFuncsScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		BlockModelService blockModelService = state.getTool().getService(BlockModelService.class);
		Listing listing = currentProgram.getListing();
		StringBuffer errorBuf = new StringBuffer();
		CodeBlockModel cbm = blockModelService.getActiveSubroutineModel();
		AddressSetView addrset =
			currentSelection == null ? (AddressSetView) currentProgram.getMemory()
					: currentSelection;
		CodeBlockIterator cbIter = cbm.getCodeBlocksContaining(addrset, monitor);
		while (cbIter.hasNext()) {
			CodeBlock block = cbIter.next();
			FunctionIterator fIter = listing.getFunctions(block, true);
			if (!fIter.hasNext()) {
				try {
					String name = "DEAD_" + block.getFirstStartAddress();
					Symbol symbol = getSymbolAt(block.getFirstStartAddress());
					if (symbol != null && !symbol.isDynamic()) {
						name = symbol.getName();
					}
					listing.createFunction(name, block.getFirstStartAddress(), block,
						SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					errorBuf.append(e.toString() + "\n");
				}
			}
		}
		if (errorBuf.length() > 0) {
			println(errorBuf.toString());
		}
	}

}
