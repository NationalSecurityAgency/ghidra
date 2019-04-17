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

import javax.swing.*;
import javax.swing.table.TableModel;

import org.junit.Before;
import org.junit.Test;

import docking.ComponentProvider;
import docking.DialogComponentProvider;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.searchtext.SearchTextPlugin;
import ghidra.app.plugin.core.string.StringTableProvider;
import ghidra.app.plugin.core.table.TableComponentProvider;

/**
 * Captures screenshots associated with Memory Search.
 */
public class SearchScreenShots extends AbstractSearchScreenShots {

	private SearchTextPlugin searchPlugin;

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();

		searchPlugin = env.getPlugin(SearchTextPlugin.class);

		env.showTool();
	}

	/**
	 * Captures the Direct References search dialog.
	 */
	@Test
	public void testDirectReferences() {

		moveTool(500, 500);

		goToListing(0x407b44, "Address", false);
		performAction("Search for Direct References", "FindPossibleReferencesPlugin", false);
		waitForSwing();

		ComponentProvider provider = getProvider(TableComponentProvider.class);
		JComponent component = provider.getComponent();
		JTable table = findComponent(component, JTable.class);
		TableModel model = table.getModel();
		waitForTableModel((ThreadedTableModel<?, ?>) model);

		captureIsolatedProvider(TableComponentProvider.class, 800, 350);
	}

	/**
	 * Captures the Direct References search dialog for a selection.
	 */
	@Test
	public void testDirectRefsOnSelection() {

		moveTool(500, 500);

		goToListing(0x407b44, "Address", false);
		makeSelection(0x40e626, 0x40e748);
		performAction("Search for Direct References", "FindPossibleReferencesPlugin", false);
		waitForSwing();

		ComponentProvider provider = getProvider(TableComponentProvider.class);
		JComponent component = provider.getComponent();
		JTable table = findComponent(component, JTable.class);
		TableModel model = table.getModel();
		waitForTableModel((ThreadedTableModel<?, ?>) model);

		captureIsolatedProvider(TableComponentProvider.class, 800, 350);
	}

	@Test
	public void testQueryResultsSearch() {

		moveTool(500, 500);

		performAction("Search Text", "SearchTextPlugin", false);
		waitForSwing();

		DialogComponentProvider dialog = getDialog();

		JRadioButton rbAll = (JRadioButton) getInstanceField("searchAllRB", dialog);
		rbAll.setSelected(true);

		JTextField textField = (JTextField) getInstanceField("valueField", dialog);
		setText(textField, "LAB");

		final JButton allButton = (JButton) getInstanceField("allButton", dialog);
		pressButton(allButton);
		waitForSwing();

		ComponentProvider provider = getProvider(TableComponentProvider.class);
		JComponent component = provider.getComponent();
		JTable table = findComponent(component, JTable.class);
		TableModel model = table.getModel();
		waitForTableModel((ThreadedTableModel<?, ?>) model);

		Window window = getWindowByTitle(null, "Search Limit Exceeded!");
		pressButtonByText(window, "OK");

		captureIsolatedProvider(TableComponentProvider.class, 500, 450);
	}

	@Test
	public void testSearchForAddressTables() {

		moveTool(500, 500);

		performAction("Search for Address Tables", "AutoTableDisassemblerPlugin", false);
		waitForSwing();

		DialogComponentProvider dialog = getDialog();
		waitForSwing();
		pressButtonByText(dialog, "Search");

		JComponent component = dialog.getComponent();
		JTable table = findComponent(component, JTable.class);
		TableModel model = table.getModel();
		waitForTableModel((ThreadedTableModel<?, ?>) model);

		captureDialog(DialogComponentProvider.class, 800, 525);
	}

	/**
	 * Captures the warning dialog displayed when the search results reach the maximum
	 * limit.
	 */
	@Test
	public void testSearchLimitExceeded() {

		moveTool(500, 500);

		// Set the search results max to a low number that we know will be hit with the 
		// custom program we've loaded.  Also, we are NOT changing the option so that dialog
		// that is shown will have the default value
		searchPlugin = env.getPlugin(SearchTextPlugin.class);
		searchPlugin.optionsChanged(null, GhidraOptions.OPTION_SEARCH_LIMIT, null, 10);

		performAction("Search Text", "SearchTextPlugin", false);
		waitForSwing();

		DialogComponentProvider dialog = getDialog();

		JRadioButton rbAll = (JRadioButton) getInstanceField("searchAllRB", dialog);
		rbAll.setSelected(true);

		JTextField textField = (JTextField) getInstanceField("valueField", dialog);
		setText(textField, "0");

		final JButton allButton = (JButton) getInstanceField("allButton", dialog);
		pressButton(allButton);

		ComponentProvider provider = getProvider(TableComponentProvider.class);
		JComponent component = provider.getComponent();
		JTable table = findComponent(component, JTable.class);
		TableModel model = table.getModel();
		waitForTableModel((ThreadedTableModel<?, ?>) model);

		Window errorDialog = waitForWindow("Search Limit Exceeded!", 2000);
		captureWindow(errorDialog);
	}

	@Test
	public void testSearchText() {

		moveTool(500, 500);

		performAction("Search Text", "SearchTextPlugin", false);
		waitForSwing();

		DialogComponentProvider dialog = getDialog();
		JCheckBox button = (JCheckBox) getInstanceField("commentsCB", dialog);
		setSelected(button, true);

		captureDialog(DialogComponentProvider.class);
	}

	@Test
	public void testStringSearchDialog() {

		moveTool(500, 500);

		performAction("Search for Strings", "StringTablePlugin", false);
		waitForSwing();

		captureDialog(DialogComponentProvider.class, 500, 325);
	}

	@Test
	public void testStringSearchResults() {

		moveTool(1000, 1000);

		performAction("Search for Strings", "StringTablePlugin", false);
		waitForSwing();

		DialogComponentProvider dialog = getDialog();
		pressButtonByText(dialog, "Search");
		waitForSwing();

		ComponentProvider provider = getProvider(StringTableProvider.class);
		JComponent component = provider.getComponent();
		JTable table = findComponent(component, JTable.class);
		TableModel model = table.getModel();
		waitForTableModel((ThreadedTableModel<?, ?>) model);

		captureIsolatedProvider(StringTableProvider.class, 1000, 750);
	}
}
