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

import java.awt.Window;

import javax.swing.JCheckBox;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import org.junit.Test;

import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.ToggleDockingAction;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.plugin.core.symtable.FilterDialog;
import ghidra.app.plugin.core.symtable.SymbolTablePlugin;

public class SymbolTablePluginScreenShots extends GhidraScreenShotGenerator {

	public SymbolTablePluginScreenShots() {
		super();
	}

	@Test
	public void testCaptureRefs_To() {
		ComponentProvider symbolProvider = getProvider("Symbol Table");
		tool.showComponentProvider(symbolProvider, true);
		moveProviderToItsOwnWindow(symbolProvider, 940, 642);

		ComponentProvider referencesProvider = showAndArrangeReferencesProvider(symbolProvider);
		setReferenceType(referencesProvider, "References To");

		GTable table = getTable(symbolProvider);
		setColumnSizes(table);
		selectRow(table, "WideCharToMultiByte");
		triggerText(table, "\n"); // hack to kick the references table

		Window window = windowForComponent(symbolProvider.getComponent());
		captureWindow(window);
	}

	@Test
	public void testCaptureInstr_From() {
		ComponentProvider symbolProvider = getProvider("Symbol Table");
		tool.showComponentProvider(symbolProvider, true);
		moveProviderToItsOwnWindow(symbolProvider, 940, 642);

		ComponentProvider referencesProvider = showAndArrangeReferencesProvider(symbolProvider);
		setReferenceType(referencesProvider, "Instruction References From");

		GTable table = getTable(symbolProvider);
		setColumnSizes(table);
		selectRow(table, "_malloc00403762");
		triggerText(table, "\n"); // hack to kick the references table

		Window window = windowForComponent(symbolProvider.getComponent());
		captureWindow(window);
	}

	@Test
	public void testCaptureData_From() {
		ComponentProvider symbolProvider = getProvider("Symbol Table");
		tool.showComponentProvider(symbolProvider, true);
		moveProviderToItsOwnWindow(symbolProvider, 940, 642);

		ComponentProvider referencesProvider = showAndArrangeReferencesProvider(symbolProvider);
		setReferenceType(referencesProvider, "Data References From");

		GTable table = getTable(symbolProvider);
		setColumnSizes(table);
		selectRow(table, "FUN_004010e0");
		triggerText(table, "\n"); // hack to kick the references table

		Window window = windowForComponent(symbolProvider.getComponent());
		captureWindow(window);
	}

	@Test
	public void testCaptureSymbol_Table() {
		ComponentProvider provider = getProvider("Symbol Table");
		tool.showComponentProvider(provider, true);

		moveProviderToItsOwnWindow(provider, 950, 400);
		GTable table = getTable(provider);
		setColumnSizes(table);

		// Pick a good section of the table:
		// entry	00401e7c	Function Label	undefined	Global	IMPORTED	1	0
		selectRow(table, "entry00401e46");

		captureProvider(provider);
	}

	@Test
	public void testCaptureFilter() {
		ComponentProvider provider = getProvider("Symbol Table");
		tool.showComponentProvider(provider, true);

		performAction("Set Filter", "SymbolTablePlugin", false);

		captureDialog(FilterDialog.class);
	}

	@Test
	public void testCaptureFilter2() {
		ComponentProvider provider = getProvider("Symbol Table");
		tool.showComponentProvider(provider, true);

		performAction("Set Filter", "SymbolTablePlugin", false);

		FilterDialog dialog =
			waitForDialogComponent(null, FilterDialog.class, DEFAULT_WINDOW_TIMEOUT);
		final JCheckBox advancedCheckBox =
			(JCheckBox) getInstanceField("advancedFilterCheckbox", dialog);

		runSwing(() -> advancedCheckBox.doClick());

		captureDialog(dialog);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private ComponentProvider showAndArrangeReferencesProvider(ComponentProvider symbolProvider) {
		ComponentProvider referencesProvider = getProvider("Symbol References");
		tool.showComponentProvider(referencesProvider, true);

		moveProvider(referencesProvider, symbolProvider, WindowPosition.BOTTOM);
		return referencesProvider;
	}

	private void setReferenceType(ComponentProvider referencesProvider, String referenceType) {

		SymbolTablePlugin plugin = env.getPlugin(SymbolTablePlugin.class);
		ToggleDockingAction action = (ToggleDockingAction) getAction(plugin, referenceType);
		performAction(action, referencesProvider, true);

		Object refProvider = getInstanceField("refProvider", plugin);
		ThreadedTableModel<?, ?> model =
			(ThreadedTableModel<?, ?>) getInstanceField("referenceKeyModel", refProvider);
		waitForTableModel(model);
	}

	private GTable getTable(ComponentProvider provider) {
		Object symbolPanel = getInstanceField("symbolPanel", provider);
		return (GTable) getInstanceField("symTable", symbolPanel);
	}

	private void setColumnSizes(final GTable table) {
		// note: these values are rough values found my trial-and-error
		runSwing(() -> {
			TableColumnModel columnModel = table.getColumnModel();
			int columnCount = columnModel.getColumnCount();
			for (int i = 0; i < columnCount; i++) {
				TableColumn column = columnModel.getColumn(i);
				Object headerValue = column.getHeaderValue();
				if ("Name".equals(headerValue)) {
					column.setPreferredWidth(300);
				}
				else if ("Reference Count".equals(headerValue)) {
					column.setPreferredWidth(25);
				}
				else if ("Offcut Ref Count".equals(headerValue)) {
					column.setPreferredWidth(25);
				}
				else if ("Namespace".equals(headerValue)) {
					column.setPreferredWidth(160);
				}
				else if ("Location".equals(headerValue)) {
					column.setPreferredWidth(170);
				}
				else if ("Source".equals(headerValue)) {
					column.setPreferredWidth(170);
				}
				else if ("Type".equals(headerValue)) {
					column.setPreferredWidth(170);
				}
			}
		});

	}
}
