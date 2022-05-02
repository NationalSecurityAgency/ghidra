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
// Developer script to generate test data. Not for general use.
//@category TestScripts
import java.util.*;

import classrecovery.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class FindOperatorDeletesAndNewsScript extends GhidraScript {
	
	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("There is no open program");
			return;
		}

		RecoveredClassHelper classHelper = new RecoveredClassHelper(currentProgram, currentLocation,
			state.getTool(), this, false, false, false, false, monitor);
		
		List<Address> discoveredOperatorDeletes =
				getFunctionAddressList(classHelper.findOperatorDeletes());
		
		BookmarkManager bookmarkMgr = currentProgram.getBookmarkManager();

		for (Address operatorDelete : discoveredOperatorDeletes) {
			monitor.checkCanceled();

			bookmarkMgr.setBookmark(operatorDelete, BookmarkType.NOTE, "TEST",
				"Found operator_delete");
		}

		List<Address> discoveredOperatorNews =
			getFunctionAddressList(classHelper.findOperatorNews());
		
		for (Address operatorNew : discoveredOperatorNews) {
			monitor.checkCanceled();

			bookmarkMgr.setBookmark(operatorNew, BookmarkType.NOTE, "TEST", "Found operator_new");
		}

	}
	
	private List<Address> getFunctionAddressList(Set<Function> functions) {

		List<Address> addresses = new ArrayList<Address>();
		for (Function function : functions) {

			addresses.add(function.getEntryPoint());
		}
		return addresses;
	}


}
