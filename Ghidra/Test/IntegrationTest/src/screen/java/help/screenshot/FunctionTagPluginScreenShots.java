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

import static org.junit.Assert.*;

import java.awt.Rectangle;

import javax.swing.JPanel;
import javax.swing.JTextField;

import org.junit.Test;

import docking.widgets.OptionDialog;
import docking.widgets.dialogs.InputDialog;
import ghidra.app.plugin.core.function.tags.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Swing;
import ghidra.util.exception.UsrException;

public class FunctionTagPluginScreenShots extends GhidraScreenShotGenerator {

	@Test
	public void testFullWindow() {
		showProvider(FunctionTagsComponentProvider.class);
		waitForSwing();
		addTableData();
		captureIsolatedProvider(FunctionTagsComponentProvider.class, 950, 400);
	}

	@Test
	public void testInputField() {
		showProvider(FunctionTagsComponentProvider.class);
		waitForSwing();
		FunctionTagsComponentProvider provider = getProvider(FunctionTagsComponentProvider.class);
		final JPanel inputPanel = (JPanel) getInstanceField("inputPanel", provider);
		captureComponent(inputPanel);
	}

	@Test
	public void testFilterField() {
		showProvider(FunctionTagsComponentProvider.class);
		waitForSwing();
		FunctionTagsComponentProvider provider = getProvider(FunctionTagsComponentProvider.class);
		final JPanel filterPanel = (JPanel) getInstanceField("filterPanel", provider);
		captureComponent(filterPanel);
	}

	/**
	 * For this test the item in row 1 of the available tags table must be an editable
	 * item. If not, edit the function_tags.xml file to remove all items and re-run this.
	 */
	@Test
	public void testEditTag() {
		showProvider(FunctionTagsComponentProvider.class);
		waitForSwing();
		addTableData();

		FunctionTagsComponentProvider provider = getProvider(FunctionTagsComponentProvider.class);
		SourceTagsPanel sourcePanel = (SourceTagsPanel) getInstanceField("sourcePanel", provider);
		FunctionTagTable table = (FunctionTagTable) getInstanceField("table", sourcePanel);
		Rectangle bounds = table.getCellRect(7, 0, false); // Cell 7 is an editable item
		doubleClick(table, bounds.x, bounds.y);

		InputDialog warningDialog = waitForDialogComponent(InputDialog.class);

		captureDialog(warningDialog);
	}

	/**
	 * Captures the warning dialog when trying to delete a tag. Note that this assumes the 
	 * tag in row 1 is NOT read-only. If that's the not the case, modify the function_tags.xml
	 * file to remove any tags that may be interfering with this.
	 * 
	 * @throws UsrException
	 */
	@Test
	public void testDeleteWarning() throws UsrException {
		showProvider(FunctionTagsComponentProvider.class);
		waitForSwing();
		addTableData();

		FunctionTagsComponentProvider provider = getProvider(FunctionTagsComponentProvider.class);
		SourceTagsPanel sourcePanel = (SourceTagsPanel) getInstanceField("sourcePanel", provider);
		FunctionTagTable table = (FunctionTagTable) getInstanceField("table", sourcePanel);
		table.setRowSelectionInterval(7, 7);
		FunctionTagButtonPanel buttonPanel =
			(FunctionTagButtonPanel) getInstanceField("buttonPanel", provider);
		pressButtonByName(buttonPanel, "deleteBtn", false);
		OptionDialog warningDialog = waitForDialogComponent(OptionDialog.class);
		captureDialog(warningDialog);
	}

	/**
	 * Captures the read-only warning when trying to edit a tag
	 * 
	 * @throws UsrException
	 */
	@Test
	public void testEditNotAllowedWarning() throws UsrException {
		showProvider(FunctionTagsComponentProvider.class);
		waitForSwing();
		addTableData();

		FunctionTagsComponentProvider provider = getProvider(FunctionTagsComponentProvider.class);
		SourceTagsPanel sourcePanel = (SourceTagsPanel) getInstanceField("sourcePanel", provider);
		FunctionTagTable table = (FunctionTagTable) getInstanceField("table", sourcePanel);
		doubleClickItem(table, "LIBRARY"); // pick a known read-only tag

		OptionDialog warningDialog = waitForDialogComponent(OptionDialog.class);
		captureDialog(warningDialog);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void doubleClickItem(FunctionTagTable table, String text) {

		FunctionTagTableModel model = (FunctionTagTableModel) table.getModel();
		int row = -1;
		for (int i = 0; i < model.getRowCount(); i++) {
			String name = (String) table.getValueAt(i, 0);
			if (name.equals(text)) {
				row = i;
				break;
			}
		}

		assertTrue("Could not find tag '" + text + "'", row > -1);

		Rectangle bounds = table.getCellRect(row, 0, true);
		doubleClick(table, bounds.x, bounds.y);
	}

	private void addTableData() {

		FunctionTagsComponentProvider provider = getProvider(FunctionTagsComponentProvider.class);

		Swing.runNow(() -> {
			provider.programActivated(program);
			navigateToFunction(provider);
		});

		JTextField inputField = (JTextField) getInstanceField("tagInputField", provider);
		setText(inputField, "Tag 2, Tag 3");
		triggerEnter(inputField);

		waitForSwing();
	}

	/**
	 * Simulates a location change on the listing so the dialog thinks the user has
	 * navigated to a function.
	 * 
	 * @param provider the component provider
	 */
	private void navigateToFunction(FunctionTagsComponentProvider provider) {
		FunctionIterator iter = program.getFunctionManager().getFunctions(true);
		while (iter.hasNext()) {
			Function func = iter.next();
			Address addr = func.getEntryPoint();
			ProgramLocation loc = new ProgramLocation(program, addr);
			provider.locationChanged(loc);

			// We only need to find one function, so exit after we've got one.
			return;
		}
	}
}
