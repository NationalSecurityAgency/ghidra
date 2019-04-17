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
package ghidra.app.plugin.core.navigation.locationreferences;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.app.actions.AbstractFindReferencesDataTypeAction;
import ghidra.app.plugin.core.symboltree.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.*;

public class SymbolTreeLocationReferencesTest extends AbstractLocationReferencesTest {

	private SymbolTreePlugin symbolTreePlugin;
	private SymbolTreeProvider treeProvider;
	private SymbolGTree symbolTree;
	private DockingActionIf showSymbolReferencesAction;

	@Override
	public void setUp() throws Exception {
		super.setUp();

		symbolTreePlugin = getPlugin(tool, SymbolTreePlugin.class);
		treeProvider = (SymbolTreeProvider) getInstanceField("provider", symbolTreePlugin);
		showProvider(tool, treeProvider.getName());
		symbolTree = (SymbolGTree) getInstanceField("tree", treeProvider);
		showSymbolReferencesAction =
			getAction(symbolTreePlugin, AbstractFindReferencesDataTypeAction.NAME);
	}

	@Test
	public void testReferencesToExternalSymbol() throws Exception {

		waitForTree(symbolTree);

		Address ref1Addr = addr(0x1001000); // ref already exists		
		Address ref2Addr = addr(0x1001010);
		Function externalFunction = addExternalFunctionReference(ref2Addr, "ADVAPI32.dll",
			"IsTextUnicode", RefType.COMPUTED_CALL);

		Address thunkAddr = addr(0x1001020);
		addThunk(thunkAddr, externalFunction);
		waitForTree(symbolTree);

		selectPath(symbolTree, "Global", "Imports", "ADVAPI32.dll", "IsTextUnicode");

		ActionContext actionContext = treeProvider.getActionContext(null);
		assertTrue("showSymbolReferencesAction not properly enabled",
			showSymbolReferencesAction.isEnabledForContext(actionContext));

		performAction(showSymbolReferencesAction, actionContext, true);

		List<LocationReference> results = getResultLocations();
		assertEquals(3, results.size());
		assertEquals(ref1Addr, results.get(0).getLocationOfUse());
		assertEquals("DATA", results.get(0).getRefTypeString());
		assertEquals(ref2Addr, results.get(1).getLocationOfUse());
		assertEquals("COMPUTED_CALL", results.get(1).getRefTypeString());
		assertEquals(thunkAddr, results.get(2).getLocationOfUse());
		assertEquals("THUNK", results.get(2).getRefTypeString());
	}

	@Test
	public void testReferencesToImportAddressTable() throws Exception {

		Address ref1Addr = addr(0x10063cc); // ref already exists

		// Add external reference which should not have any impact on reference to IAT location/label
		Address otherRefAddr = addr(0x1001010);
		addExternalFunctionReference(otherRefAddr, "ADVAPI32.dll", "IsTextUnicode",
			RefType.COMPUTED_CALL);

		selectPath(symbolTree, "Global", "Labels", "ADVAPI32.dll_IsTextUnicode"); // label on IAT entry

		ActionContext actionContext = treeProvider.getActionContext(null);
		assertTrue("showSymbolReferencesAction not properly enabled",
			showSymbolReferencesAction.isEnabledForContext(actionContext));

		performAction(showSymbolReferencesAction, actionContext, true);

		List<LocationReference> results = getResultLocations();
		assertEquals(1, results.size());
		assertEquals(ref1Addr, results.get(0).getLocationOfUse());
		assertEquals("INDIRECTION", results.get(0).getRefTypeString());

	}

	private Function addExternalFunctionReference(Address refAddr, String libraryName,
			String extLabel, RefType refType) throws Exception {

		List<ExternalLocation> locations =
			program.getExternalManager().getExternalLocations(libraryName, extLabel);
		assertEquals(1, locations.size());
		ExternalLocation externalLocation = locations.get(0);

		assertNotNull("External location not found: " + libraryName + "::" + extLabel,
			externalLocation);
		int txId = program.startTransaction("Add Ext Ref");
		try {
			program.getReferenceManager().addExternalReference(refAddr, 1, externalLocation,
				SourceType.USER_DEFINED, refType);
			return externalLocation.createFunction();
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private void addThunk(Address thunkAddr, Function thunkedFunction) throws Exception {
		int txId = program.startTransaction("Add Thunk");
		try {
			Function f = program.getFunctionManager().createFunction(null, thunkAddr,
				new AddressSet(thunkAddr), SourceType.USER_DEFINED);
			f.setThunkedFunction(thunkedFunction);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

}
