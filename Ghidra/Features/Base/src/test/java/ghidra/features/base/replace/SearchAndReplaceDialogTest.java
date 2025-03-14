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
package ghidra.features.base.replace;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.features.base.quickfix.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.symbol.SymbolManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.test.*;

public class SearchAndReplaceDialogTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private ProgramDB program;
	private DockingActionIf searchAndReplaceAction;
	private SearchAndReplaceDialog dialog;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(SearchAndReplacePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());

		SearchAndReplacePlugin plugin = getPlugin(tool, SearchAndReplacePlugin.class);

		ToyProgramBuilder builder = new ToyProgramBuilder("Test", true);
		builder.createLabel("0x100", "myFooLabel");
		builder.createLabel("0x200", "myBarLabel");
		program = builder.getProgram();
		env.open(program);
		env.showTool();
		searchAndReplaceAction = getAction(plugin, "Search And Replace");
		ActionContext actionContext = tool.getActiveComponentProvider().getActionContext(null);
		performAction(searchAndReplaceAction, actionContext, false);
		dialog = waitForDialogComponent(SearchAndReplaceDialog.class);
		assertNotNull(dialog);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testBasicEnablementAndStatus() {
		assertEquals("Please enter search text", getStatusText());
		assertFalse(isOkEnabled());

		enterText("search text", "replace text");

		assertFalse(isOkEnabled());
		assertEquals("Please select at least one \"search for\" item to search!", getStatusText());

		selectSearchType("Labels");

		assertEquals("", getStatusText());
		assertTrue(isOkEnabled());
	}

	@Test
	public void testInvalidRegex() {
		enterText("(abc", "");		// "(abc" is valid for normal search, invalid for regex
		selectSearchType("Labels");
		assertEquals("", getStatusText());
		assertTrue(isOkEnabled());

		selectRegEx(true);
		assertEquals("", getStatusText());
		assertFalse(isOkEnabled());

		selectRegEx(false);
		assertEquals("", getStatusText());
		assertTrue(isOkEnabled());
	}

	@Test
	public void testResultsProviderAppearsWithResults() {
		SearchAndReplaceProvider provider = executeBasicQuery();
		List<QuickFix> data = provider.getTableModel().getModelData();
		assertEquals(2, data.size());
		assertEquals(QuickFixStatus.NONE, data.get(0).getStatus());
		assertEquals(QuickFixStatus.NONE, data.get(1).getStatus());
	}

	@Test
	public void testApplyResults() {
		SearchAndReplaceProvider provider = executeBasicQuery();
		List<QuickFix> data = provider.getTableModel().getModelData();
		assertEquals(2, data.size());
		executeAllItems(provider);
		assertEquals(QuickFixStatus.DONE, data.get(0).getStatus());
		assertEquals(QuickFixStatus.DONE, data.get(1).getStatus());
		assertEquals("yourFooLabel", getSymbol(0x100).getName());
		assertEquals("yourBarLabel", getSymbol(0x200).getName());
	}

	@Test
	public void testApplyResultsToJustSelectedItem() {
		SearchAndReplaceProvider provider = executeBasicQuery();
		List<QuickFix> data = provider.getTableModel().getModelData();
		assertEquals(2, data.size());
		selectItem(provider, 0);
		executeSelectedItems(provider);
		assertEquals(QuickFixStatus.DONE, data.get(0).getStatus());
		assertEquals(QuickFixStatus.NONE, data.get(1).getStatus());
		assertEquals("myFooLabel", getSymbol(0x100).getName());
		assertEquals("yourBarLabel", getSymbol(0x200).getName());
		assertEquals(1, getSelectedRow(provider));
	}

	private int getSelectedRow(SearchAndReplaceProvider provider) {
		return runSwing(() -> provider.getSelectedRow());
	}

	private void selectItem(SearchAndReplaceProvider provider, int index) {
		runSwing(() -> provider.setSelection(index, index));
	}

	private Symbol getSymbol(long offset) {
		SymbolManager symbolTable = program.getSymbolTable();
		Symbol primarySymbol = symbolTable.getPrimarySymbol(addr(offset));
		return primarySymbol;
	}

	private void executeAllItems(SearchAndReplaceProvider provider) {
		runSwing(() -> provider.executeAll());
		waitForTasks();
	}

	private void executeSelectedItems(SearchAndReplaceProvider provider) {
		runSwing(() -> provider.applySelected());
		waitForTasks();
	}

	private Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private SearchAndReplaceProvider executeBasicQuery() {
		enterText("my", "your");
		selectSearchType("Labels");
		pressOk();
		SearchAndReplaceProvider provider =
			waitForComponentProvider(SearchAndReplaceProvider.class);
		assertNotNull(provider);
		QuickFixTableModel tableModel = provider.getTableModel();
		waitForTableModel(tableModel);
		return provider;
	}

	private void pressOk() {
		runSwing(() -> dialog.okCallback());
	}

	private void selectRegEx(boolean b) {
		runSwing(() -> dialog.selectRegEx(b));
	}

	private boolean isOkEnabled() {
		return runSwing(() -> dialog.isOkEnabled());
	}

	private void selectSearchType(String searchType) {
		runSwing(() -> dialog.selectSearchType(searchType));
	}

	private void enterText(String searchText, String replaceText) {
		runSwing(() -> dialog.setSarchAndReplaceText(searchText, replaceText));
	}

	private String getStatusText() {
		return runSwing(() -> dialog.getStatusText().trim());
	}

}
