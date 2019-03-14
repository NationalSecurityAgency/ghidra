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
package ghidra.app.nav;

import docking.ComponentProvider;
import docking.DockingWindowManager;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.SystemUtilities;

public class NavigationUtils {
	public static Navigatable getActiveNavigatable() {
		DockingWindowManager activeInstance = DockingWindowManager.getActiveInstance();
		if (activeInstance == null) {
			return null;
		}
		ComponentProvider focusedComponentProvider = activeInstance.getActiveComponentProvider();
		if (focusedComponentProvider instanceof Navigatable) {
			return (Navigatable) focusedComponentProvider;
		}
		return null;
	}

	public static void setSelection(PluginTool tool, Navigatable navigatable,
			ProgramSelection selection) {
		if (navigatable == null) {
			GoToService service = tool.getService(GoToService.class);
			if (service == null) {
				return;	// can't do anything here
			}
		}

		SystemUtilities.runIfSwingOrPostSwingLater(() -> {
			navigatable.setSelection(selection);
			tool.contextChanged(null);
		});
	}

	/**
	 * Locate all possible linkage addresses which correspond to the specified external address.
	 * This will correspond to either a generic reference type (DATA or EXTERNAL_REF) on a pointer
	 * or a thunk to the external location.  Both pointers and thunk contructs are utilized to 
	 * perform dynamic linking between programs and external libraries they reference.  These
	 * linkage locations facilitate the function calls into any dynamically
	 * linked external program (i.e., library).
	 * @param program
	 * @param externalAddr external location address
	 * @return array of possible linkage addresses found
	 */
	public static Address[] getExternalLinkageAddresses(Program program, Address externalAddr) {
		if (!externalAddr.isExternalAddress()) {
			return null;
		}

		AddressSet set = new AddressSet();
		Listing listing = program.getListing();

		ReferenceIterator iter = program.getReferenceManager().getReferencesTo(externalAddr);
		while (iter.hasNext()) {
			Reference ref = iter.next();
			RefType refType = ref.getReferenceType();
			if (refType == RefType.DATA || refType == RefType.EXTERNAL_REF) {
				Data data = listing.getDefinedDataAt(ref.getFromAddress());
				if (data != null && (data.getDataType() instanceof Pointer)) {
					set.add(ref.getFromAddress());
				}
			}
		}

		findExternalThunkLinkages(program, externalAddr, set);

		Address[] linkAddresses = new Address[(int) set.getNumAddresses()];
		int index = 0;
		for (Address addr : set.getAddresses(true)) {
			linkAddresses[index++] = addr;
		}

		return linkAddresses;
	}

	/**
	 * Locate direct thunks to the external function identified by externalAddr.  Only consider
	 * those thunks whose function body does not refer to an address contained within the linkageSet
	 * provided.
	 * @param program
	 * @param externalAddr external location address
	 * @param linkageSet set of previously discovered pointer linkages to the external
	 * location.  This set will be updated with any thunk linkage locations found.
	 */
	private static void findExternalThunkLinkages(Program program, Address externalAddr,
			AddressSet linkageSet) {
		Symbol s = program.getSymbolTable().getPrimarySymbol(externalAddr);
		if (s == null || s.getSymbolType() != SymbolType.FUNCTION) {
			return;
		}
		Function extFunc = (Function) s.getObject();
		Address[] thunkAddrs = extFunc.getFunctionThunkAddresses();
		if (thunkAddrs == null) {
			return;
		}
		for (Address thunkAddr : thunkAddrs) {
			Function f = program.getListing().getFunctionAt(thunkAddr);
			if (f != null && !hasLinkageReference(program, f, linkageSet)) {
				// only add thunk its function body does not refer to a known linkage location
				linkageSet.add(thunkAddr);
			}
		}
	}

	/**
	 * Determine if the specified thunkFunction's body contains any references to addresses 
	 * contained within the linkageSet provided.
	 * @param thunkFunction possible linkage thunk
	 * @param linkageSet set of previously discovered linkage pointer locations
	 * @return true if function contains one or more references to addresses contained
	 * within the linkageSet of addresses, else false
	 */
	private static boolean hasLinkageReference(Program program, Function thunkFunction,
			AddressSetView linkageSet) {
		ReferenceManager referenceManager = program.getReferenceManager();
		for (Address addr : referenceManager.getReferenceSourceIterator(thunkFunction.getBody(),
			true)) {
			for (Reference ref : referenceManager.getReferencesFrom(addr)) {
				if (linkageSet.contains(ref.getToAddress())) {
					return true;
				}
			}
		}
		return false;
	}
}
