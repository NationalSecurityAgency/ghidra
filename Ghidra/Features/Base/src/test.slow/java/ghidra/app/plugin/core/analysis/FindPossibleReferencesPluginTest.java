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
package ghidra.app.plugin.core.analysis;

import static org.junit.Assert.*;

import org.junit.*;

import docking.ComponentProvider;
import docking.action.DockingActionIf;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.GThreadedTablePanel;
import docking.widgets.table.threaded.ThreadedTableModel;
import generic.test.TestUtils;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.plugin.core.table.TableServicePlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class FindPossibleReferencesPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private AddressFactory addrFactory;
	private CodeBrowserPlugin codeBrowser;

	private FindPossibleReferencesPlugin plugin;
	private ComponentProvider provider;
	private GTable table;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.showTool();
		tool.addPlugin(FindPossibleReferencesPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		codeBrowser = env.getPlugin(CodeBrowserPlugin.class);
		plugin = env.getPlugin(FindPossibleReferencesPlugin.class);

	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
    public void testOneHit() throws Exception {
		openProgram(build32BitX86());
		doSearch("010010e0");
		assertEquals(1, table.getRowCount());
		assertEquals(addr("01002cff"), table.getModel().getValueAt(0, 0));
		assertTrue(provider.getTitle().contains("010010e0"));
	}

	@Test
    public void testNoHits() throws Exception {
		openProgram(build32BitX86());
		doSearch("010010e2");
		assertEquals(0, table.getRowCount());
	}

	@Test
    public void testSelection() throws Exception {
		openProgram(build32BitX86());
		select("010010e0", "010010f0");
		doSearch("01001000");// When you have a selection, it does NOT search for the single
								// address in the selection, instead, it bizarrely searches the
								// entire program for all the addresses in the selection.
		assertEquals(1, table.getRowCount());
		assertEquals(addr("01002cff"), table.getModel().getValueAt(0, 0));
	}

	@Test
    public void testSelectionWithNoHits() throws Exception {
		openProgram(build32BitX86());
		select("01002d99", "01002d69");
		doSearch("01001000");
		assertEquals(0, table.getRowCount());
	}

	@Test
    public void testRestoreSelection() throws Exception {
		openProgram(build32BitX86());

		select("010010e0", "010010f0");
		doSearch("01003ac2");

		assertEquals(1, table.getRowCount());
		assertTrue(provider.getTitle().contains("Selection @ 010010e0"));

		clearSelection();

		assertEquals(new ProgramSelection(),
			TestUtils.invokeInstanceMethod("getCurrentSelection", codeBrowser));

		DockingActionIf restoreSelectionAction =
			getAction(plugin, FindPossibleReferencesPlugin.RESTORE_SELECTION_ACTION_NAME);
		assertNotNull(restoreSelectionAction);
		performAction(restoreSelectionAction, true);

		assertEquals(new ProgramSelection(addr("10010e0"), addr("10010f0")),
			TestUtils.invokeInstanceMethod("getCurrentSelection", codeBrowser));
	}

	@Test
    public void testFilterAlignment() throws Exception {
		openProgram(build32BitX86());

		doSearch("0x11223344");

		assertEquals(6, table.getRowCount());

		align(2);
		assertEquals(4, table.getRowCount());

		align(4);
		assertEquals(3, table.getRowCount());

		align(8);
		assertEquals(2, table.getRowCount());

		align(1);
		assertEquals(6, table.getRowCount());
	}

	@Test
    public void test8051() throws Exception {
		openProgram(build8051());
		doSearch("CODE:1234");
		assertEquals(1, table.getRowCount());
		assertEquals(addr("CODE:2000"), table.getModel().getValueAt(0, 0));
		assertTrue(provider.getTitle().contains("CODE:1234"));
	}

	@Test
    public void test20BitRealMode() throws Exception {
		openProgram(build20Bit());
		doSearch("0000:1234");
		assertEquals(1, table.getRowCount());
		assertEquals(addr("1000:2000"), table.getModel().getValueAt(0, 0));
		assertTrue(provider.getTitle().contains("0000:1234"));

		// test that segment is not used
		doSearch("abcd:1234");
		assertEquals(1, table.getRowCount());
		assertEquals(addr("1000:2000"), table.getModel().getValueAt(0, 0));
		assertTrue(provider.getTitle().contains("0000:1234"));

	}

	private void align(int i) {
		DockingActionIf alignAction = getAction(plugin, "UpdateAlignmentAction" + i);
		assertNotNull(alignAction);
		performAction(alignAction, true);
		ThreadedTableModel<?, ?> model = (ThreadedTableModel<?, ?>) table.getModel();
		waitForTableModel(model);
	}

	private void select(String start, String end) {
		ProgramSelection selection = new ProgramSelection(addr(start), addr(end));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", selection, program));
	}

	private void clearSelection() {
		ProgramSelection selection = new ProgramSelection();
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", selection, program));
	}

	private Program build32BitX86() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._X86);
		builder.createMemory("test", "0x01001000", 0x1000);
		builder.setBytes("0x01002cf5",
			"55 8b ec 83 7d 14 00 56 8b 35 e0 10 00 01 57 74 09 ff 75 14 ff d6 8b f8 eb 02 33 ff ff 75 10 ff d6 03 c7 8d 44 00 02 50 6a 40 ff 15 dc 10 00 01 8b f0 85 f6 74 27 56 ff 75 14 ff 75 10 e8 5c ff ff ff ff 75 18 ff 75 0c 56 ff 75 08 ff 15 04 12 00 01 56 8b f8 ff 15 c0 10 00 01 eb 14 ff 75 18 ff 75 0c ff 75 10 ff 75 08 ff 15 04 12 00 01 8b f8 8b c7 5f 5e 5d c2 14");
		builder.disassemble("0x01002cf5", 0x121, true);
		builder.createFunction("0x01002cf5");

		builder.setBytes("0x11223344", "00 00 00 00");
		builder.setBytes("0x1001500", "44 33 22 11");
		builder.setBytes("0x1001511", "44 33 22 11");
		builder.setBytes("0x1001522", "44 33 22 11");
		builder.setBytes("0x1001533", "44 33 22 11");
		builder.setBytes("0x1001544", "44 33 22 11");
		builder.setBytes("0x1001588", "44 33 22 11");
		return builder.getProgram();
	}

	private Program build8051() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("test", ProgramBuilder._8051);

		builder.setBytes("CODE:1234", "00 00 00 00");
		builder.setBytes("CODE:2000", "12 34");
		return builder.getProgram();
	}

	private Program build20Bit() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("test", ProgramBuilder._X86_16_REAL_MODE);

		builder.setBytes("0000:1234", "00 00 00 00");
		builder.setBytes("1000:2000", "34 12");
		return builder.getProgram();
	}

	private void openProgram(Program p) throws Exception {
		ProgramManager pm = tool.getService(ProgramManager.class);
		program = p;
		pm.openProgram(program.getDomainFile());
		addrFactory = program.getAddressFactory();
	}

	private void doSearch(String loc) throws Exception {
		codeBrowser.goToField(addr(loc), "Address", 0, 0);
		DockingActionIf action =
			getAction(plugin, FindPossibleReferencesPlugin.SEARCH_DIRECT_REFS_ACTION_NAME);
		assertNotNull(action);
		performAction(action, codeBrowser.getProvider(), true);

		waitForTableToLoad();
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	private void waitForTableToLoad() {
		int sleepyTime = 50;
		int totalTime = 0;

		while (provider == null && totalTime < 2000) {
			sleep(sleepyTime);
			totalTime += sleepyTime;
			loadProvider();
		}
	}

	private void loadProvider() {
		TableServicePlugin tableService = getPlugin(tool, TableServicePlugin.class);
		TableComponentProvider<?>[] providers = tableService.getManagedComponents();
		if (providers.length == 0) {
			return;
		}

		GThreadedTablePanel<?> panel = providers[0].getThreadedTablePanel();
		table = panel.getTable();
		provider = providers[0];

		ThreadedTableModel<?, ?> model = (ThreadedTableModel<?, ?>) table.getModel();
		waitForTableModel(model);
	}

}
