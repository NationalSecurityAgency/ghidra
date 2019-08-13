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
package ghidra.app.plugin.core.module;

import static org.junit.Assert.*;

import javax.swing.SwingUtilities;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.plugin.core.programtree.ViewProviderService;
import ghidra.app.services.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.GroupPath;
import ghidra.program.util.LabelFieldLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class AutoRenamePluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private AutoRenamePlugin plugin;
	private DockingActionIf renameAction;
	private DockingActionIf labelAction;
	private ProgramTreeService service;
	private CodeBrowserPlugin cb;

	public AutoRenamePluginTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(ProgramTreePlugin.class.getName());
		tool.addPlugin(AutoRenamePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());

		plugin = env.getPlugin(AutoRenamePlugin.class);
		cb = env.getPlugin(CodeBrowserPlugin.class);
		renameAction = getAction(plugin, "Rename Fragment from Program Tree View");
		labelAction = getAction(plugin, "Rename Fragment from Code Browser");

		service = tool.getService(ProgramTreeService.class);

		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test1", "0x1001000", 0x4000);

		// Main Tree
		builder.createProgramTree("Main Tree");
		builder.createFragment("Main Tree", "DLLs", "USER32.DLL", "0x10011a8", "0x10012bf");

		builder.createMemoryCallReference("0x01003597", "0x010033f6");

		builder.createLabel("0x010011a8", "USER32.dll_IsDialogMessageW");

		program = builder.getProgram();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

// for debug
//		env.showTool();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testActionEnabled() {
		setViewToMainTree();

		// set the selection for a Folder
		ProgramModule root = program.getListing().getRootModule("Main Tree");
		GroupPath[] gps = new GroupPath[1];
		gps[0] = new GroupPath(new String[] { root.getName(), "DLLs" });
		setSelection(gps);

		ViewManagerService vmService = tool.getService(ViewManagerService.class);
		ViewProviderService vps = vmService.getCurrentViewProvider();

		Object context = vps.getActivePopupObject(null);

		assertTrue(!renameAction.isEnabledForContext(createContext(context)));
		assertTrue(!labelAction.isEnabledForContext(createContext(context)));

		gps = new GroupPath[1];
		gps[0] = new GroupPath(new String[] { root.getName(), "DLLs", "USER32.DLL" });
		setSelection(gps);

		context = vps.getActivePopupObject(null);
		assertTrue(renameAction.isEnabledForContext(createContext(context)));
		assertTrue(!labelAction.isEnabledForContext(createContext(context)));

		// fire Label program location
		Address addr = getAddr(0x10033f6);
		LabelFieldLocation loc = new LabelFieldLocation(program, addr, "SUB_010033f6");
		tool.firePluginEvent(new ProgramLocationPluginEvent("test", loc, program));

		ActionContext actionContext = cb.getProvider().getActionContext(null);
		assertTrue(!renameAction.isEnabledForContext(actionContext));
		assertTrue(labelAction.isEnabledForContext(actionContext));
	}

	@Test
	public void testRename() throws Exception {
		setViewToMainTree();

		ProgramModule root = program.getListing().getRootModule("Main Tree");

		GroupPath[] gps = new GroupPath[1];
		gps[0] = new GroupPath(new String[] { root.getName(), "DLLs", "USER32.DLL" });
		ProgramFragment frag = program.getListing().getFragment("Main Tree", "USER32.DLL");
		String origName = frag.getName();
		Symbol s = program.getSymbolTable().getPrimarySymbol(frag.getMinAddress());
		setSelection(gps);

		ViewManagerService vmService = tool.getService(ViewManagerService.class);
		ViewProviderService vps = vmService.getCurrentViewProvider();
		Object context = vps.getActivePopupObject(null);
		performAction(renameAction, createContext(context), true);
		program.flushEvents();

		assertNotNull(program.getListing().getFragment("Main Tree", s.getName()));
		assertNull(program.getListing().getFragment("Main Tree", origName));

	}

	@Test
	public void testRenameLabel() throws Exception {
		setViewToMainTree();

		Address addr = getAddr(0x010033f6);
		ProgramFragment frag = program.getListing().getFragment("Main Tree", addr);
		String origName = frag.getName();
		final LabelFieldLocation loc =
			new LabelFieldLocation(program, addr, null, "SUB_010033f6", null, 0, 0);
		cb.goTo(loc);

		SwingUtilities.invokeAndWait(
			() -> labelAction.actionPerformed(cb.getProvider().getActionContext(null)));
		program.flushEvents();
		assertNull(program.getListing().getFragment("SUB_010033f6", origName));
		assertEquals("SUB_010033f6", frag.getName());
	}

	private Address getAddr(int offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

	private void setViewToMainTree() {
		runSwing(() -> service.setViewedTree("Main Tree"));
	}

	private void setSelection(final GroupPath[] gps) {

		runSwing(() -> service.setGroupSelection(gps));
	}

}
