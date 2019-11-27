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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.*;

import org.junit.*;

import docking.action.DockingActionIf;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.plugin.core.programtree.ViewProviderService;
import ghidra.app.services.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.*;
import ghidra.program.util.GroupPath;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class ModuleSortPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private ModuleSortPlugin plugin;
	private Set<DockingActionIf> actions;
	private ProgramTreeService service;

	public ModuleSortPluginTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(ProgramTreePlugin.class.getName());
		tool.addPlugin(ModuleSortPlugin.class.getName());
		List<Plugin> list = tool.getManagedPlugins();
		for (int i = 0; i < list.size(); i++) {
			Plugin p = list.get(i);
			if (p.getClass() == ModuleSortPlugin.class) {
				plugin = (ModuleSortPlugin) p;
				break;
			}
		}
		actions = getActionsByOwner(tool, plugin.getName());
		service = tool.getService(ProgramTreeService.class);

		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test1", "0x1001000", 0x1000);
		builder.createMemory("test2", "0x1007000", 0x1000);

		// Main Tree
		builder.createProgramTree("Main Tree");
		builder.createFragment("Main Tree", "DLLs", "USER32.DLL", "0x10011a8", "0x10012bf");

		// Strings
		builder.createFragment("Main Tree", "Strings.C", "010074d4", "0x10074d4", "0x10074e3");
		builder.createFragment("Main Tree", "Strings.C", "01007492", "0x1007492", "0x100749c");
		builder.createFragment("Main Tree", "Strings.G", "010074ae", "0x10074ae", "0x10074bb");
		builder.createFragment("Main Tree", "Strings.S", "0100746c", "0x100746c", "0x100747a");
		builder.createFragment("Main Tree", "Strings.S", "010074be", "0x10074be", "0x10074d0");
		builder.createFragment("Main Tree", "Strings.S", "010074a0", "0x10074a0", "0x10074aa");
		builder.createFragment("Main Tree", "Strings.L", "0100747e", "0x100747e", "0x100748f");

		builder.createMemoryCallReference("0x01003597", "0x010033f6");

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
	public void testActionsEnabled() {

		setViewToMainTree();

		// set the selection for a Folder
		ProgramModule root = program.getListing().getRootModule("Main Tree");
		GroupPath[] gps = new GroupPath[1];
		gps[0] = new GroupPath(new String[] { root.getName(), "DLLs" });
		setSelection(gps);

		ViewManagerService vmService = tool.getService(ViewManagerService.class);
		ViewProviderService vps = vmService.getCurrentViewProvider();

		Object context = vps.getActivePopupObject(null);
		for (DockingActionIf action : actions) {

			assertTrue(action.isAddToPopup(vps.getActionContext(null)));
		}

		gps = new GroupPath[1];
		gps[0] = new GroupPath(new String[] { root.getName(), "DLLs", "USER32.DLL" });
		service.setGroupSelection(gps);

		context = vps.getActivePopupObject(null);
		for (DockingActionIf action : actions) {
			assertTrue(!action.isAddToPopup(vps.getActionContext(null)));
		}
	}

	@Test
	public void testSortByName() throws Exception {

		setViewToMainTree();

		// set the selection for a Folder
		ProgramModule root = program.getListing().getRootModule("Main Tree");
		GroupPath[] gps = new GroupPath[1];
		gps[0] = new GroupPath(new String[] { root.getName(), "Strings" });
		setSelection(gps);

		ProgramModule stringsModule = program.getListing().getModule("Main Tree", "Strings");
		Group[] kids = stringsModule.getChildren();
		String[] names = new String[] { "C", "G", "S", "L" };
		for (int i = 0; i < names.length; i++) {
			assertEquals(names[i], kids[i].getName());
		}
		int transactionID = program.startTransaction("Test");
		ProgramFragment f = program.getListing().getFragment("Main Tree", "0100746c");
		f.setName("X-0100746c");

		f = program.getListing().getFragment("Main Tree", "010074be");
		f.setName("Q-010074be");

		f = program.getListing().getFragment("Main Tree", "010074a0");
		f.setName("B-010074a0");

		program.endTransaction(transactionID, true);
		program.flushEvents();

		ViewManagerService vmService = tool.getService(ViewManagerService.class);
		ViewProviderService vps = vmService.getCurrentViewProvider();

		for (DockingActionIf action : actions) {
			if (action.getName().indexOf("Name") > 0) {

				action.actionPerformed(vps.getActionContext(null));
				break;
			}
		}
		program.flushEvents();
		Arrays.sort(names);
		kids = stringsModule.getChildren();
		for (int i = 0; i < names.length; i++) {
			assertEquals(names[i], kids[i].getName());
		}

		ProgramModule m = program.getListing().getModule("Main Tree", "S");
		kids = m.getChildren();
		assertEquals("B-010074a0", kids[0].getName());
		assertEquals("Q-010074be", kids[1].getName());
		assertEquals("X-0100746c", kids[2].getName());
	}

	@Test
	public void testSortByAddress() {
		// need to set the tree view as "Main Tree"
		setViewToMainTree();

		// set the selection for a Folder
		ProgramModule root = program.getListing().getRootModule("Main Tree");
		GroupPath[] gps = new GroupPath[1];
		gps[0] = new GroupPath(new String[] { root.getName(), "Strings" });
		setSelection(gps);

		ProgramModule sModule = program.getListing().getModule("Main Tree", "S");
		Group[] kids = sModule.getChildren();
		String[] names = new String[] { "0100746c", "010074be", "010074a0" };
		for (int i = 0; i < names.length; i++) {
			assertEquals(names[i], kids[i].getName());
		}
		ViewManagerService vmService = tool.getService(ViewManagerService.class);
		ViewProviderService vps = vmService.getCurrentViewProvider();

		Object context = vps.getActivePopupObject(null);

		for (DockingActionIf action : actions) {
			if (action.getName().indexOf("Address") > 0) {
				action.actionPerformed(vps.getActionContext(null));
				break;
			}
		}
		program.flushEvents();
		kids = sModule.getChildren();
		assertEquals("0100746c", kids[0].getName());
		assertEquals("010074a0", kids[1].getName());
		assertEquals("010074be", kids[2].getName());

		ProgramModule m = program.getListing().getModule("Main Tree", "Strings");
		kids = m.getChildren();
		assertEquals("S", kids[0].getName());
		assertEquals("L", kids[1].getName());
		assertEquals("C", kids[2].getName());
		assertEquals("G", kids[3].getName());

	}

	@Test
	public void testProgramClosed() {
		env.close(program);
		ViewManagerService vmService = tool.getService(ViewManagerService.class);
		ViewProviderService vps = vmService.getCurrentViewProvider();

		Object context = vps.getActivePopupObject(null);
		for (DockingActionIf action : actions) {
			assertTrue(!action.isAddToPopup(vps.getActionContext(null)));
		}
	}

	private void setViewToMainTree() {
		runSwing(() -> service.setViewedTree("Main Tree"));
	}

	private void setSelection(final GroupPath[] gps) {

		runSwing(() -> service.setGroupSelection(gps));
	}
}
