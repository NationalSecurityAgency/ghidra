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
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.EquateTable;
import util.CollectionUtils;

//Shows all equates found within the current program selection or the current function.
//@category    Examples
//@menupath    
//@keybinding  
//@toolbar    
public class ShowEquatesInSelectionScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		AddressSetView scope = currentSelection;
		if (scope == null) {

			// see if we are inside of a function
			Function function = getFunctionContaining(currentAddress);
			if (function == null) {
				println("Please make a selection or place the cursor in a function");
				return;
			}

			scope = function.getBody();
		}

		EquateTable equateTable = currentProgram.getEquateTable();
		AddressIterator it = equateTable.getEquateAddresses(scope);
		List<Address> addresses = CollectionUtils.asList((Iterable<Address>) it);
		show(addresses.toArray(new Address[addresses.size()]));
	}
}
