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
package help.screenshot;

import javax.swing.JTextField;

import org.junit.Test;

import docking.widgets.tree.GTree;
import ghidra.app.plugin.core.symboltree.EditExternalLocationDialog;
import ghidra.app.plugin.core.symboltree.SymbolTreeProvider;
import ghidra.app.util.AddressInput;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.*;

public class SymbolTreePluginScreenShots extends GhidraScreenShotGenerator {

	public SymbolTreePluginScreenShots() {
		super();
	}

	@Test
	public void testSymbolTree() {
		showProvider(SymbolTreeProvider.class);
		SymbolTreeProvider provider = getProvider(SymbolTreeProvider.class);
		GTree tree = (GTree) getInstanceField("tree", provider);
		expandPath(tree, "Global", "Exports");
		expandTree(tree, "Global", "Labels");
		captureIsolatedProvider(provider, 400, 600);
	}

	@Test
	public void testCreateExternalLocation() {

		final EditExternalLocationDialog dialog =
			new EditExternalLocationDialog(program, "TestLibrary");
		dialog.setTitle("Create External Location");
		showDialogWithoutBlocking(tool, dialog);

		Object panel = getInstanceField("extLocPanel", dialog);
		JTextField textField = (JTextField) getInstanceField("extLibPathTextField", panel);
		setText(textField, "/Test/libraryA");
		JTextField extLabelTextField = (JTextField) getInstanceField("extLabelTextField", panel);
		extLabelTextField.setText("Sample");
		AddressInput extAddressInputWidget =
			(AddressInput) getInstanceField("extAddressInputWidget", panel);
		extAddressInputWidget.setAddress(addr(0x010012345));
		captureDialog();

	}

	@Test
	public void testEditExternalLocation() throws Exception {
		ExternalLocation extLoc;
		int txId = program.startTransaction("Test");
		try {
			ExternalManager extMgr = program.getExternalManager();
			Library lib = extMgr.addExternalLibraryName("TestLibrary", SourceType.IMPORTED);
			extLoc = extMgr.addExtFunction("TestLibrary", "??1type_info@@UEAA@XZ",
				addr(0x010012345), SourceType.IMPORTED);
			GhidraClass typeInfoClass =
				program.getSymbolTable().createClass(lib, "type_info", SourceType.ANALYSIS);
			extLoc.setName(typeInfoClass, "~type_info", SourceType.ANALYSIS);
		}
		finally {
			program.endTransaction(txId, true);
		}

		final EditExternalLocationDialog dialog = new EditExternalLocationDialog(extLoc);
		dialog.setTitle("Edit External Location");

		showDialogWithoutBlocking(tool, dialog);

		Object panel = getInstanceField("extLocPanel", dialog);
		JTextField textField = (JTextField) getInstanceField("extLibPathTextField", panel);
		setText(textField, "/Test/libraryA");

		captureDialog();

	}

}
