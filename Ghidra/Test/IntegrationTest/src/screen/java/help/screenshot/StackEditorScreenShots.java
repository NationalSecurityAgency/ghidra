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

import java.awt.Rectangle;
import java.awt.Window;

import javax.swing.JTable;
import javax.swing.table.TableModel;

import org.junit.Test;

import ghidra.app.plugin.core.stackeditor.StackEditorProvider;
import ghidra.app.util.viewer.field.FunctionSignatureFieldFactory;
import ghidra.util.exception.AssertException;

public class StackEditorScreenShots extends GhidraScreenShotGenerator {

	public StackEditorScreenShots() {
		super();
	}

	@Test
	public void testStackEditor() throws Exception {

		goToListing(0x40699c);

		positionCursor(0x40699c, FunctionSignatureFieldFactory.FIELD_NAME);
		performAction("Edit Stack Frame", "StackEditorManagerPlugin", false);
		waitForSwing();

		StackEditorProvider provider = (StackEditorProvider) getProvider("Stack Editor");

		final JTable table = provider.getTable();
		waitForSwing();

		moveProviderToItsOwnWindow(provider);
		Window window = windowForComponent(table);
		setWindowSize(window, 650, 350);

		selectTableRow(table, "param_3");
		waitForSwing();

		captureProvider(provider);
	}

	@Test
	public void testNumElementsPrompt() {
		goToListing(0x40699c);

		positionCursor(0x40699c, FunctionSignatureFieldFactory.FIELD_NAME);
		performAction("Edit Stack Frame", "StackEditorManagerPlugin", false);
		waitForSwing();

		StackEditorProvider stackEditor = (StackEditorProvider) getProvider("Stack Editor");

		final JTable table = stackEditor.getTable();
		waitForSwing();

		selectTableRow(table, "param_3");
		waitForSwing();

		performAction("Editor: Create Array", "StackEditorManagerPlugin", stackEditor, false);
		waitForSwing();
		captureDialog();

	}

	private void selectTableRow(final JTable table, final String text) {

		final TableModel model = table.getModel();
		runSwing(() -> {
			int columnCount = model.getColumnCount();
			int columnIndex = -1;
			int rowIndex = -1;
			for (int i1 = 0; i1 < columnCount; i1++) {
				if (model.getColumnName(i1).equals("Name")) {
					columnIndex = i1;
					break;
				}
			}
			if (columnIndex != -1) {
				int rowCount = model.getRowCount();
				for (int i2 = 0; i2 < rowCount; i2++) {
					if (model.getValueAt(i2, columnIndex).equals(text)) {
						rowIndex = i2;
						break;
					}
				}
			}
			if (rowIndex == -1) {
				throw new AssertException();
			}
			table.setRowSelectionInterval(rowIndex, rowIndex);

			Rectangle rect = table.getCellRect(rowIndex, columnIndex, true);
			table.scrollRectToVisible(rect);
		});
	}
}
