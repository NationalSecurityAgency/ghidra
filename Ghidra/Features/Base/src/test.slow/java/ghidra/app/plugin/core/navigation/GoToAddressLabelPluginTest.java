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
package ghidra.app.plugin.core.navigation;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Set;

import javax.swing.JCheckBox;

import org.junit.*;

import docking.ActionContext;
import docking.DefaultActionContext;
import docking.action.DockingActionIf;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.GThreadedTablePanel;
import generic.test.TestUtils;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.label.CreateNamespacesCmd;
import ghidra.app.cmd.refs.AddMemRefCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.progmgr.MultiTabPlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.plugin.core.table.TableServicePlugin;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.SearchConstants;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.navigation.GoToAddressLabelDialog;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableNameFieldLocation;
import ghidra.test.*;
import ghidra.util.Swing;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

public class GoToAddressLabelPluginTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private GoToAddressLabelPlugin plugin;
	private GoToAddressLabelDialog dialog;
	private CodeBrowserPlugin cbPlugin;
	private CodeViewerProvider provider;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(ProgramManagerPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(MultiTabPlugin.class.getName());

		plugin = env.getPlugin(GoToAddressLabelPlugin.class);
		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);
		provider = cbPlugin.getProvider();
		showTool(tool);
		dialog = plugin.getDialog();
		setCaseSensitive(true);
	}

	@After
	public void tearDown() {
		closeAllWindows();
		env.dispose();
	}

	@Test
	public void testActionEnablement() throws Exception {
		Set<DockingActionIf> actions = getActionsByOwner(tool, plugin.getName());
		assertEquals(1, actions.size());
		assertEquals("Go To Address/Label", CollectionUtils.any(actions).getName());
		ActionContext actionContext = getActionContext();
		assertFalse(CollectionUtils.any(actions).isEnabledForContext(actionContext));

		loadProgram("x86");

		actionContext = getActionContext();
		assertTrue(CollectionUtils.any(actions).isEnabledForContext(actionContext));
		final ProgramManager pm = tool.getService(ProgramManager.class);
		runSwing(() -> pm.closeProgram(program, true));
		actionContext = getActionContext();
		assertFalse(CollectionUtils.any(actions).isEnabledForContext(actionContext));
	}

	@Test
	public void testGoTox86() throws Exception {
		loadProgram("x86");
		setText("100493b");
		performOkCallback();
		assertEquals(addr("0x100493b"), cbPlugin.getCurrentAddress());

		setText("1001000");
		showDialog();
		performOkCallback();
		assertEquals(addr("0x1001000"), cbPlugin.getCurrentAddress());

		setText("entry");
		showDialog();
		performOkCallback();
		assertEquals(addr("0x1006420"), cbPlugin.getCurrentAddress());
		assertFalse(dialog.isVisible());

		setText("bad input");
		showDialog();
		performOkCallback();
		assertTrue(dialog.isVisible());
		assertEquals(addr("0x1006420"), cbPlugin.getCurrentAddress());

		List<String> history = dialog.getHistory();
		assertEquals(3, history.size());
		assertEquals("entry", history.get(0));
		assertEquals("1001000", history.get(1));
		assertEquals("100493b", history.get(2));

		setText("1001000");
		performOkCallback();
		assertEquals(addr("0x1001000"), cbPlugin.getCurrentAddress());

		setText("ENTRY");
		showDialog();
		performOkCallback();
		assertTrue(dialog.isVisible());
		assertEquals(addr("0x1001000"), cbPlugin.getCurrentAddress());
		// nothing found, case sensitive is "on"

		dialog.setCaseSensitive(false);
		performOkCallback();

		TableServicePlugin tablePlugin = getPlugin(tool, TableServicePlugin.class);
		TableComponentProvider<?>[] providers = tablePlugin.getManagedComponents();
		assertEquals(0, providers.length);
		assertEquals(addr("0x1006420"), cbPlugin.getCurrentAddress());
	}

	@Test
	public void testGoTo8051() throws Exception {
		loadProgram("8051");

		setText("CODE:000b");
		performOkCallback();
		assertEquals(addr("CODE:000b"), cbPlugin.getCurrentAddress());

		setText("BITS:b3");
		performOkCallback();
		assertEquals(addr("BITS:b3"), cbPlugin.getCurrentAddress());

		setText("INTMEM:0f");
		performOkCallback();
		assertEquals(addr("INTMEM:0f"), cbPlugin.getCurrentAddress());

		setText("FUN_CODE_075d");
		performOkCallback();
		assertEquals(addr("CODE:075d"), cbPlugin.getCurrentAddress());

		setText("TXSTAT");
		performOkCallback();
		assertEquals(addr("SFR:F2"), cbPlugin.getCurrentAddress());

		setText("INT*");
		performOkCallback();

		TableServicePlugin tablePlugin = getPlugin(tool, TableServicePlugin.class);
		TableComponentProvider<?>[] providers = tablePlugin.getManagedComponents();
		assertEquals(1, providers.length);
		close(providers[0]);
		providers = tablePlugin.getManagedComponents();
		assertEquals(0, providers.length);
	}

	@Test
	public void testAddressExpression() throws Exception {
		loadProgram("x86");
		setText("100493b");
		performOkCallback();
		assertEquals(addr("0x100493b"), cbPlugin.getCurrentAddress());

		setText("+12");
		showDialog();
		performOkCallback();
		assertEquals(addr("0x100494d"), cbPlugin.getCurrentAddress());
	}

	@Test
	public void testGoToFileOffset() throws Exception {
		loadProgram("x86");
		Memory mem = program.getMemory();

		//@formatter:off
		// Create a 4-byte and a 1-byte memory block using a 4-byte source FileBytes (just an array
		// in this case). The 2nd block's byte should share a file byte with the first block so we
		// can get multiple results when doing a Go To on that file offset.
		byte[] bytes =
		/* Block1      |---|---|---|---|   */
		/* FileBytes*/ { 1,  2,  3,  4 }   ;
		/* Block2                  |---|   */
		//@formatter:on

		// Create FileBytes-based memory blocks
		Address addr1 = addr("0x2000");
		Address addr2 = addr("0x3000");
		tx(program, () -> {
			FileBytes fileBytes1 = MemoryBlockUtils.createFileBytes(program,
				new ByteArrayProvider(program.getName() + "1", bytes), TaskMonitor.DUMMY);
			FileBytes fileBytes2 = MemoryBlockUtils.createFileBytes(program,
				new ByteArrayProvider(program.getName() + "2", bytes), TaskMonitor.DUMMY);
			mem.createInitializedBlock("FileBytes1", addr1, fileBytes1, 0, 4, false);
			mem.createInitializedBlock("FileBytes2", addr2, fileBytes2, 3, 1, false);
		});

		// Test decimal
		setText("file(0)");
		showDialog();
		performOkCallback();
		assertEquals(addr1, cbPlugin.getCurrentAddress());

		// Test hex
		setText("file(0x1)");
		showDialog();
		performOkCallback();
		assertEquals(addr1.add(1), cbPlugin.getCurrentAddress());

		// Test "case"
		setText("FILe(0X2)");
		showDialog();
		performOkCallback();
		assertEquals(addr1.add(2), cbPlugin.getCurrentAddress());

		// Test spaces
		setText("file   (   0   )");
		showDialog();
		performOkCallback();
		assertEquals(addr1, cbPlugin.getCurrentAddress());

		// Test not found
		setText("file(0x100)");
		showDialog();
		performOkCallback();
		assertNotEquals(addr1.add(0x100), cbPlugin.getCurrentAddress());

		// Test multiple results
		setText("file(3)");
		showDialog();
		performOkCallback();
		GhidraProgramTableModel<?> model = waitForModel();
		assertEquals(2, model.getRowCount());
	}

	@Test
	public void testScopedSymbol() throws Exception {
		loadProgram("x86");
		CreateNamespacesCmd cmd = new CreateNamespacesCmd("MyNamespace", SourceType.USER_DEFINED);
		tool.execute(cmd, program);
		Namespace namespace = cmd.getNamespace();
		AddLabelCmd cmd2 =
			new AddLabelCmd(addr("0x100494d"), "Bob", namespace, SourceType.USER_DEFINED);
		tool.execute(cmd2, program);
		AddLabelCmd cmd3 = new AddLabelCmd(addr("0x100493b"), "Bob", SourceType.USER_DEFINED);
		tool.execute(cmd3, program);

		setText("MyNamespace::Bob");
		performOkCallback();
		assertEquals(addr("0x100494d"), cbPlugin.getCurrentAddress());
		showDialog();
		setText("Bob");
		performOkCallback();
		GhidraProgramTableModel<?> model = waitForModel();
		assertEquals(2, model.getRowCount());
	}

	@Test
	public void testWildcardInBlock() throws Exception {

		loadProgram("x86");
		MemoryBlock block = createOverlay("TestOverlay", "1002000", 100);
		String name = block.getName();

		AddLabelCmd cmd = new AddLabelCmd(addr(name + "::1002000"), "Bob", SourceType.USER_DEFINED);
		tool.execute(cmd, program);

		// try a wildcard for an address in the new block (this gets us an extra code path tested)
		setText(name + "::*ob");
		performOkCallback();
		assertEquals(addr("TestOverlay::1002000"), cbPlugin.getCurrentAddress());
	}

	@Test
	public void testSymbolInMemoryBlock() throws Exception {
		loadProgram("x86");
		createLabel("1008000", "Bob");
		showDialog();
		setText(".text::Bob");
		performOkCallback();
		assertEquals(addr("0x1008000"), cbPlugin.getCurrentAddress());
	}

	@Test
	public void testMatchingAddressInOverlay_ShowAllAddressesOn() throws Exception {
		//
		// Tests that the GoTo service will show a table of address matches when the user
		// queries an address has multiple matches.
		//
		loadProgram("x86");
		createOverlay("TestOverlay", "1002000", 100);
		assumeCurrentAddressSpace(false);
		showDialog();
		setText("1002000");
		performOkCallback();
		GhidraProgramTableModel<?> model = waitForModel();
		assertEquals(2, model.getRowCount());
	}

	@Test
	public void testMatchingAddressInOverlay_ShowAllAddressesOff() throws Exception {
		//
		// Tests that the GoTo service will not show a table of address matches when the user
		// queries an address has multiple matches *and* the option to always show all
		// addresses is off *and* the current address space has a matching address.
		//
		loadProgram("x86");
		createOverlay("TestOverlay", "1002000", 100);

		//
		// Turn off the option to show all addresses when there is a match in our current
		// address space
		//
		assertTrue(cbPlugin.goTo(new ProgramLocation(program, addr("1001000")))); // known good location

		showDialog();
		setText("1002000");
		performOkCallback();
		assertEquals(addr("0x1002000"), cbPlugin.getCurrentAddress());
	}

	@Test
	public void testMatchingAddressInOverlay_NoMatchInCurrentAddressSpace() throws Exception {
		//
		// Tests that the GoTo service will show a table of address matches when the user
		// queries an address that does not have an entry in the current address space *and* the
		// option to always show all addresses is off.
		//
		loadProgram("x86");
		createOverlay("TestOverlay1", "1002000", 100);
		MemoryBlock overlay2Block = createOverlay("TestOverlay2", "1003000", 100);

		//
		// Put us in an address space that does not have a match for the query address
		// The default space and 'Test Overlay 1' each have an address for 1002000.  The
		// 'Test Overlay 2' does not.  So, put the cursor there.
		String name = overlay2Block.getName();
		assertTrue(cbPlugin.goTo(new ProgramLocation(program, addr(name + "::1003000"))));

		showDialog();
		setText("1002000");
		performOkCallback();
		GhidraProgramTableModel<?> model = waitForModel();
		assertEquals(2, model.getRowCount());
	}

	@Test
	public void testExactSearchNotFound() throws Exception {
		loadProgram("x86");
		setText("100493b");
		performOkCallback();
		assertEquals(addr("0x100493b"), cbPlugin.getCurrentAddress());

		showDialog();
		setCaseSensitive(true);
		setIncludeDynamicSymbols(false);
		setText("Bob");
		performOkCallback();
		assertEquals(addr("0x100493b"), cbPlugin.getCurrentAddress());
		assertTrue(dialog.isVisible());

	}

	@Test
	public void testNoDynamicCaseInsensitive() throws Exception {
		loadProgram("x86");
		setText("100493b");
		performOkCallback();
		assertEquals(addr("0x100493b"), cbPlugin.getCurrentAddress());

		showDialog();
		setCaseSensitive(false);
		setIncludeDynamicSymbols(false);
		setText("ENTRY");
		performOkCallback();
		assertEquals(addr("0x1006420"), cbPlugin.getCurrentAddress());

	}

	@Test
	public void testDynamicCaseSensitive() throws Exception {

		loadProgram("x86");
		CreateDataCmd cmd = new CreateDataCmd(addr("0x10015a4"), new TerminatedUnicodeDataType());
		tool.execute(cmd, program);

		AddMemRefCmd addMemRefCmd = new AddMemRefCmd(addr("0x100493b"), addr("0x10015a4"),
			RefType.DATA, SourceType.USER_DEFINED, 0);
		tool.execute(addMemRefCmd, program);

		Data data = program.getListing().getDataAt(addr("0x10015a4"));
		assertEquals("fSavePageSettings", data.getValue());

		setText("100493b");
		performOkCallback();
		assertEquals(addr("0x100493b"), cbPlugin.getCurrentAddress());

		showDialog();
		setCaseSensitive(true);
		setIncludeDynamicSymbols(true);
		setText("u_fSavePageSettings_010015a4");
		performOkCallback();
		assertEquals(addr("0x010015a4"), cbPlugin.getCurrentAddress());

	}

	@Test
	public void testNoDynamicCaseInsensitiveDoesNotMatchDynamic() throws Exception {
		loadProgram("x86");

		CreateDataCmd cmd = new CreateDataCmd(addr("0x10015a4"), new TerminatedUnicodeDataType());
		tool.execute(cmd, program);

		AddMemRefCmd addMemRefCmd = new AddMemRefCmd(addr("0x100493b"), addr("0x10015a4"),
			RefType.DATA, SourceType.USER_DEFINED, 0);
		tool.execute(addMemRefCmd, program);

		Data data = program.getListing().getDataAt(addr("0x10015a4"));
		assertEquals("fSavePageSettings", data.getValue());

		setText("100493b");
		performOkCallback();
		assertEquals(addr("0x100493b"), cbPlugin.getCurrentAddress());

		setCaseSensitive(false);
		setIncludeDynamicSymbols(false);

		showDialog();
		setText("*SavePage*");
		performOkCallback();
		assertTrue(dialog.isVisible());

	}

	@Test
	public void testSeg() throws Exception {
		loadProgram("segmented");

		setText("1000:0036");
		performOkCallback();
		assertEquals(addr("1000:0036"), cbPlugin.getCurrentAddress());

		setText("132c:0847");
		performOkCallback();
		assertEquals(addr("132c:0847"), cbPlugin.getCurrentAddress());

		setText("entry");
		performOkCallback();
		assertEquals(addr("1000:0000"), cbPlugin.getCurrentAddress());

		setText("LAB_1000_0037");
		performOkCallback();
		assertEquals(addr("1000:0037"), cbPlugin.getCurrentAddress());

		setText("s_*");
		performOkCallback();

		TableServicePlugin tablePlugin = getPlugin(tool, TableServicePlugin.class);
		TableComponentProvider<?>[] providers = tablePlugin.getManagedComponents();
		assertEquals(1, providers.length);
		close(providers[0]);
		TableComponentProvider<?>[] newProviders = tablePlugin.getManagedComponents();
		assertEquals(0, newProviders.length);
	}

	@Test
	public void testQueryResults() throws Exception {
		loadProgram("x86");

		setText("entry");
		performOkCallback();
		assertEquals(addr("1006420"), cbPlugin.getCurrentAddress());

		setText("rsrc_S*");
		performOkCallback();

		GhidraProgramTableModel<?> model = waitForModel();
		assertEquals("0100def8", model.getValueAt(0, 0).toString());
		assertEquals("0100e2f8", model.getValueAt(1, 0).toString());
		assertEquals("0100eb90", model.getValueAt(2, 0).toString());
		assertEquals("0100f1d0", model.getValueAt(3, 0).toString());

		TableComponentProvider<?>[] providers = getProviders();
		assertEquals(1, providers.length);
		close(providers[0]);
		providers = getProviders();
		assertEquals(0, providers.length);

		showDialog();
		setText("xyzabc*"); // no matches
		performOkCallback();

		assertEquals("No results for xyzabc*", dialog.getStatusText());
		runSwing(() -> dialog.close());
	}

	@Test
	public void testQueryResults2() throws Exception {
		loadProgram("x86");

		setText("entry");
		performOkCallback();
		assertEquals(addr("1006420"), cbPlugin.getCurrentAddress());

		setText("ghi*");
		performOkCallback();

		TableComponentProvider<?>[] providers = getProviders();
		assertEquals(0, providers.length);
		assertEquals(addr("1002cf5"), cbPlugin.getCurrentAddress());
	}

	@Test
	public void testQueryResultsDialogCaseSensitive() throws Exception {
		loadProgram("x86");
		setText("Ghi*");
		performOkCallback();
		assertEquals("No results for Ghi*", dialog.getStatusText());
	}

	@Test
	public void testQueryResultsMaxHitsDynamicFound() throws Exception {
		loadProgram("x86");
		Options opt = plugin.getTool().getOptions(SearchConstants.SEARCH_OPTION_NAME);
		opt.setInt(SearchConstants.SEARCH_LIMIT_NAME, 20);

		setText("L*");
		performOkCallback();
		GhidraProgramTableModel<?> model = waitForModel();
		assertEquals(20, model.getRowCount());
	}

	@Test
	public void testQueryResultsMaxHitsDefinedFound() throws Exception {
		loadProgram("x86");
		Options opt = plugin.getTool().getOptions(SearchConstants.SEARCH_OPTION_NAME);
		opt.setInt(SearchConstants.SEARCH_LIMIT_NAME, 5);

		createLabel("1006960", "abc1");
		createLabel("1006961", "abc2");
		createLabel("1006962", "abc3");
		createLabel("1006963", "abc4");
		createLabel("1006964", "abc5");
		createLabel("1006965", "abc6");
		createLabel("1006966", "abc7");

		setText("abc*");
		performOkCallback();
		GhidraProgramTableModel<?> model = waitForModel();
		assertEquals(5, model.getRowCount());
	}

	@Test
	public void testQueryResultsDialogCaseSensitive2() throws Exception {
		loadProgram("x86");
		Symbol symbol = getUniqueSymbol(program, "comdlg32.dll_PageSetupDlgW");

		tx(program, () -> {
			symbol.setName("COmlg32.dll_PageSetupDlgW", SourceType.USER_DEFINED);
		});

		setText("COm*");
		performOkCallback();

		TableComponentProvider<?>[] providers = getProviders();
		assertEquals(0, providers.length);
	}

	@Test
	public void testQueryResultsDialogNotCaseSensitive() throws Exception {
		loadProgram("x86");
		Symbol symbol = getUniqueSymbol(program, "comdlg32.dll_PageSetupDlgW");
		tx(program, () -> {
			symbol.setName("COmlg32.dll_PageSetupDlgW", SourceType.USER_DEFINED);
		});
		setCaseSensitive(false);
		setText("COm*");
		performOkCallback();

		GhidraProgramTableModel<?> model = waitForModel();
		assertEquals(3, model.getRowCount());

		TableComponentProvider<?>[] providers = getProviders();
		close(providers[0]);
	}

	@Test
	public void testQueryResultsDialogNavigation() throws Exception {
		loadProgram("x86");

		setText("rsrc_S*");
		performOkCallback();

		GhidraProgramTableModel<?> model = waitForModel();
		assertEquals(4, model.getRowCount());
		TableComponentProvider<?>[] providers = getProviders();
		GThreadedTablePanel<?> panel =
			(GThreadedTablePanel<?>) TestUtils.getInstanceField("threadedPanel", providers[0]);
		GTable table = panel.getTable();

		assertEquals("0100def8", model.getValueAt(0, 0).toString());
		assertEquals("0100e2f8", model.getValueAt(1, 0).toString());
		assertEquals("0100eb90", model.getValueAt(2, 0).toString());
		assertEquals("0100f1d0", model.getValueAt(3, 0).toString());

		clickTableCell(table, 2, 0, 2);
		assertEquals(addr("0100eb90"), cbPlugin.getCurrentAddress());

		close(providers[0]);
	}

	@Test
	public void testNextPrevious() throws Exception {
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		NextPrevAddressPlugin np = env.getPlugin(NextPrevAddressPlugin.class);
		DockingActionIf next = getAction(np, "Next Location in History");
		DockingActionIf prev = getAction(np, "Previous Location in History");
		DockingActionIf clear = getAction(np, "Clear History Buffer");
		assertFalse(clear.isEnabledForContext(provider.getActionContext(null)));
		assertFalse(next.isEnabledForContext(provider.getActionContext(null)));
		assertFalse(prev.isEnabledForContext(provider.getActionContext(null)));

		loadProgram("x86");

		assertFalse(clear.isEnabledForContext(provider.getActionContext(null)));
		assertFalse(next.isEnabledForContext(provider.getActionContext(null)));
		assertFalse(prev.isEnabledForContext(provider.getActionContext(null)));

		setText("100493b");
		performOkCallback();
		assertEquals(addr("100493b"), cbPlugin.getCurrentAddress());

		clear.actionPerformed(new DefaultActionContext());
		assertFalse(clear.isEnabledForContext(provider.getActionContext(null)));
		assertFalse(next.isEnabledForContext(provider.getActionContext(null)));
		assertFalse(prev.isEnabledForContext(provider.getActionContext(null)));

		setText("1001000");
		performOkCallback();
		assertEquals(addr("1001000"), cbPlugin.getCurrentAddress());
		waitForSwing();
		assertTrue(clear.isEnabledForContext(provider.getActionContext(null)));
		assertFalse(next.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(prev.isEnabledForContext(provider.getActionContext(null)));

		prev.actionPerformed(new DefaultActionContext());
		assertEquals(addr("100493b"), cbPlugin.getCurrentAddress());

		assertTrue(next.isEnabledForContext(provider.getActionContext(null)));
		assertFalse(prev.isEnabledForContext(provider.getActionContext(null)));

		next.actionPerformed(new DefaultActionContext());
		assertEquals(addr("1001000"), cbPlugin.getCurrentAddress());

		setText("1001010");
		performOkCallback();
		assertEquals(addr("1001010"), cbPlugin.getCurrentAddress());
		waitForSwing();
		assertFalse(next.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(prev.isEnabledForContext(provider.getActionContext(null)));

		prev.actionPerformed(new DefaultActionContext());
		prev.actionPerformed(new DefaultActionContext());

		assertEquals(addr("100493b"), cbPlugin.getCurrentAddress());
		assertTrue(next.isEnabledForContext(provider.getActionContext(null)));
		assertFalse(prev.isEnabledForContext(provider.getActionContext(null)));

		setText("1001020");
		performOkCallback();
		assertEquals(addr("1001020"), cbPlugin.getCurrentAddress());
		waitForSwing();
		assertFalse(next.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(prev.isEnabledForContext(provider.getActionContext(null)));

	}

	@Test
	public void testGoToVariableSymbol() throws Exception {
		loadProgram("x86.exe");

		Function function = program.getFunctionManager().getFunctionAt(addr("0x01006420"));
		Variable[] locals = function.getLocalVariables();
		setText(locals[locals.length - 1].getName());
		performOkCallback();

		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertTrue(loc instanceof VariableNameFieldLocation);

		VariableNameFieldLocation vloc = (VariableNameFieldLocation) loc;
		assertEquals(locals[locals.length - 1].getName(), vloc.getName());
	}

	@Test
	public void testGoExternalSymbolEndUpOnThunk() throws Exception {
		loadProgram("x86.exe");
		setText("rand");
		performOkCallback();
		assertEquals(addr("0x1002000"), cbPlugin.getCurrentAddress());
	}

	@Test
	public void testGoToDefaultDynamicStringLabel() throws Exception {
		// s_GDI32.dll_010070bc

		loadProgram("x86.exe");

		setText("s_GDI32.dll_010070bc");
		performOkCallback();
		ProgramLocation loc = cbPlugin.getCurrentLocation();
		assertEquals(addr("010070bc"), loc.getAddress());
	}

	@Test
	public void testSaveRestoreState() throws Exception {
		int maxEntries = plugin.getMaximumGotoEntries();

		loadProgram("x86.exe");
		Memory memory = program.getMemory();

		int count = 0;
		SymbolIterator iter = program.getSymbolTable().getAllSymbols(true);
		while (iter.hasNext() && count < 30) {
			Symbol symbol = iter.next();
			Address addr = symbol.getAddress();
			if ((addr.isMemoryAddress() && !memory.contains(addr)) || addr.isExternalAddress()) {
				continue;
			}
			setText(symbol.getName());
			performOkCallback();
			++count;
		}

		SaveState saveState = new SaveState("test");
		plugin.writeDataState(saveState);

		plugin.readDataState(saveState);

		GhidraComboBox<?> combo = findComponent(dialog, GhidraComboBox.class);
		assertNotNull(combo);
		assertEquals(maxEntries, combo.getModel().getSize());
	}

	@Test
	public void testTableModelSearch_DynamicSymbols() throws Exception {

		//
		// Note: the meat of testing non-dynamic symbols is in SymbolManagerTest
		//

		loadProgram("x86");
		setText("*");
		setCaseSensitive(true);
		performOkCallback();

		GhidraProgramTableModel<?> model = waitForModel();
		List<?> list = model.getModelData();
		assertTrue("A wildcard search did not find all symbols, found " + list, list.size() > 20);
	}

	@Test
	public void testNavigateToOtherProgramOption_FunctionName() throws Exception {
		loadProgram("x86");
		loadProgram("8051");
		showDialog();
		setText("FUN_01002c93");
		performOkCallback();
		assertTrue("Expected goto to fail and dialog to still be showing", dialog.isShowing());

		setOptionToAllowNavigationToOtherOpenPrograms();
		performOkCallback();

		assertFalse("Expected goto to succeed and dialog to be gone", dialog.isShowing());
	}

	@Test
	public void testNavigateToOtherProgramOption_AddressString() throws Exception {
		loadProgram("x86");
		loadProgram("8051");
		showDialog();
		setText("01002c93");
		performOkCallback();
		assertTrue("Expected goto to fail and dialog to still be showing", dialog.isShowing());

		setOptionToAllowNavigationToOtherOpenPrograms();
		performOkCallback();

		assertFalse("Expected goto to succeed and dialog to be gone", dialog.isShowing());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void setOptionToAllowNavigationToOtherOpenPrograms() throws Exception {
		runSwing(() -> {
			ToolOptions options = tool.getOptions("Navigation");
			options.setBoolean("'Go To' in Current Program Only", false);
		});
	}

	private void loadProgram(String programName) throws Exception {

		program = doLoadProgram(programName);
		Assert.assertNotNull(program);

		final ProgramManager pm = tool.getService(ProgramManager.class);
		runSwing(() -> pm.openProgram(program.getDomainFile()));
		program.release(this);
		addrFactory = program.getAddressFactory();
	}

	private Program doLoadProgram(String programName) throws Exception {
		switch (programName) {
			case "x86":
			case "x86.exe":
				return buildProgram_X86(programName);
			case "8051":
				return buildProgram_8051();
			case "segmented":
				return buildProgram_segmented();
		}
		Assert.fail("Don't know how to open program " + programName);
		return null; // can't get here
	}

	private Program buildProgram_X86(String name) throws Exception {

		ClassicSampleX86ProgramBuilder builder =
			new ClassicSampleX86ProgramBuilder(name, false, this);

		//
		// Labels
		//
		builder.createLabel("0x010012f0", "comdlg32.dll_PageSetupDlgW");
		builder.createLabel("0x0100def8", "rsrc_String_3_3fe");
		builder.createLabel("0x0100e2f8", "rsrc_String_1_24a");
		builder.createLabel("0x0100eb90", "rsrc_String_4_5c8");

		//
		// String data
		//
		// "fSavePageSettings"
		builder.setBytes("0x10015a4", "66 00 53 00 61 00 76 00 65 00 50 00 61 00 67 00 65 00 " +
			"53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00");
		// "GDI32.dll"
		builder.setBytes("0x010070bc", "47 44 49 33 32 2e 64 6c 6c 00");

		// create an arbitrary reference in order to create a default label
		builder.applyDataType("0x010070bc", new TerminatedStringDataType(), 1);
		builder.createMemoryReadReference("0x01006420", "0x010070bc");
		builder.setBytes("0x1002000", "01 02 03 04 05 06 07 08");
		builder.applyDataType("0x1002000", new PointerDataType());
		builder.createExternalReference("0x1002000", "extlib", "rand", 0);
		//
		// Local variable for testing go to
		//

		ProgramDB p = builder.getProgram();
		tx(p, () -> {
			FunctionManager fm = p.getFunctionManager();
			Function f = fm.getFunctionAt(builder.addr("0x01006420"));
			ByteDataType dt = new ByteDataType();
			Variable var = new LocalVariableImpl("bob.local", 0, dt, builder.addr("0x01006421"), p);
			f.addLocalVariable(var, SourceType.USER_DEFINED);
		});

		return p;
	}

	private Program buildProgram_8051() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._8051, this);
		builder.createMemory("CODE", "CODE:0000", 0x1948);
		builder.setBytes("CODE:07ea", "f5 55", true);
		builder.setBytes("CODE:03f8", "30 02 03", true);
		builder.setBytes("CODE:0595", "75 55 1b", true);

		builder.createMemory("INTMEM", "INTMEM:00", 0x8);
		builder.createMemory("INTMEM", "INTMEM:08", 0x8);
		builder.createMemory("INTMEM", "INTMEM:10", 0x8);
		builder.createMemory("INTMEM", "INTMEM:18", 0x8);
		builder.createMemory("INTMEM", "INTMEM:20", 0xE0);
		builder.createMemory("SFR", "SFR:80", 0x80);
		builder.createMemory("BITS", "BITS:00", 0x80);
		builder.createMemory("BITS", "BITS:80", 0x80);

		builder.createEmptyFunction("FUN_CODE_075d", "CODE:075d", 0x20, DataType.DEFAULT);
		builder.createEmptyFunction("FUN1", "CODE:03f0", 0x20, DataType.DEFAULT);
		builder.createEmptyFunction("FUN2", "CODE:07d0", 0x20, DataType.DEFAULT);

		builder.createLabel("SFR:F2", "TXSTAT");

		builder.createLabel("INTMEM:00", "INT1");
		builder.createLabel("INTMEM:00", "INT2");
		builder.createLabel("INTMEM:00", "INT3");

		return builder.getProgram();
	}

	private Program buildProgram_segmented() throws Exception {
		ProgramBuilder builder =
			new ProgramBuilder("segmented", ProgramBuilder._X86_16_REAL_MODE, this);
		builder.createMemory("Seg_0", "1000:0000", 0x32c0);
		builder.createMemory("Seg_1", "132c:0000", 0x9be);
		builder.setBytes("1000:03ea", "7e 09");
		builder.disassemble("1000:03ea", 2);

		builder.setBytes("1000:0154", "ff 36 84 00");
		builder.disassemble("1000:0154", 4);

		builder.applyDataType("132c:0084", new WordDataType(), 1);
		builder.createMemoryReference("1000:0154", "1000:0037", RefType.CONDITIONAL_JUMP,
			SourceType.ANALYSIS);

		builder.createLabel("1000:0000", "entry");
		builder.createLabel("1000:0001", "s_one");
		builder.createLabel("1000:0001", "s_two");
		builder.createLabel("1000:0001", "s_three");

		return builder.getProgram();
	}

	private ActionContext getActionContext() {
		ActionContext context = runSwing(() -> cbPlugin.getProvider().getActionContext(null));
		if (context == null) {
			context = new DefaultActionContext();
		}
		return context;
	}

	private MemoryBlock createOverlay(String name, String address, long size) throws Exception {
		int transactionID = program.startTransaction("Test");
		try {
			Memory memory = program.getMemory();
			return memory.createInitializedBlock(name, addr(address), size, (byte) 0,
				TaskMonitor.DUMMY, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	private GhidraProgramTableModel<?> waitForModel() throws Exception {
		TableComponentProvider<?> tableProvider =
			waitForComponentProvider(TableComponentProvider.class);
		GhidraProgramTableModel<?> model = tableProvider.getModel();
		waitForTableModel(model);
		return model;
	}

	private TableComponentProvider<?>[] getProviders() {
		TableServicePlugin tableServicePlugin = getPlugin(tool, TableServicePlugin.class);
		return tableServicePlugin.getManagedComponents();
	}

	private void createLabel(String address, String name) {
		AddLabelCmd cmd = new AddLabelCmd(addr(address), name, SourceType.USER_DEFINED);
		tool.execute(cmd, program);
	}

	private void setCaseSensitive(final boolean selected) {
		final JCheckBox checkBox =
			(JCheckBox) TestUtils.getInstanceField("caseSensitiveBox", dialog);
		runSwing(() -> checkBox.setSelected(selected));
	}

	private void setIncludeDynamicSymbols(final boolean selected) {
		final JCheckBox checkBox =
			(JCheckBox) TestUtils.getInstanceField("includeDynamicBox", dialog);
		runSwing(() -> checkBox.setSelected(selected));
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	private void showDialog() {
		Swing.runLater(() -> dialog.show(provider, cbPlugin.getCurrentAddress(), tool));
		waitForSwing();
	}

	private void setText(final String text) throws Exception {
		runSwing(() -> dialog.setText(text));
	}

	private void performOkCallback() throws Exception {
		runSwing(() -> dialog.okCallback());
	}

	private void assumeCurrentAddressSpace(boolean b) {
		runSwing(() -> {
			Options options = tool.getOptions(NavigationOptions.NAVIGATION_OPTIONS);
			options.setBoolean(NavigationOptions.ASSUME_CURRENT_ADDRESS_SPACE, b);
		});
	}

	private void close(TableComponentProvider<?> c) {
		runSwing(c::closeComponent);
	}

}
