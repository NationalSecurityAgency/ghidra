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

import org.junit.Test;

import docking.action.DockingActionIf;
import ghidra.app.plugin.core.search.DecompilerTextFinderDialog;
import ghidra.app.plugin.core.search.TextMatch;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.util.table.GhidraProgramTableModel;

public class DecompilerTextFinderPluginScreenShots extends GhidraScreenShotGenerator {

	@Test
	public void testDecompilerTextFinderDialog() {

		DockingActionIf action = getAction(tool, "Search Decompiled Text");
		performAction(action, false);
		captureDialog();
		closeAllWindows();
	}

	@Test
	public void testDecompilerTextFinderResultsTable() {

		DockingActionIf action = getAction(tool, "Search Decompiled Text");
		performAction(action, false);
		DecompilerTextFinderDialog searchDialog =
			waitForDialogComponent(DecompilerTextFinderDialog.class);

		String searchText = " = '\\0'";
		runSwing(() -> searchDialog.setSearchText(searchText));
		pressButtonByText(searchDialog, "Search", false);

		@SuppressWarnings("unchecked")
		TableComponentProvider<TextMatch> tableProvider =
			waitForComponentProvider(TableComponentProvider.class);
		GhidraProgramTableModel<TextMatch> model = tableProvider.getModel();
		waitForTableModel(model);

		// TOD capture entire window?
		captureProvider(tableProvider);
		close(searchDialog);
	}
}
