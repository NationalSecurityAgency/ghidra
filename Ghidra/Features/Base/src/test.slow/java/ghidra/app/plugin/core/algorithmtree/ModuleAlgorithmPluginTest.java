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
package ghidra.app.plugin.core.algorithmtree;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Set;

import org.junit.*;

import docking.action.DockingActionIf;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.plugin.core.programtree.ViewProviderService;
import ghidra.app.services.ProgramTreeService;
import ghidra.app.services.ViewManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.util.GroupPath;
import ghidra.test.*;
import util.CollectionUtils;

/**
 * Test the module algorithm plugin gui elements.
 */
public class ModuleAlgorithmPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private ModuleAlgorithmPlugin plugin;
	private Set<DockingActionIf> actions;
	private ProgramTreeService service;
	private Object context;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();
		tool = env.launchDefaultTool(program);

		tool.addPlugin(ProgramTreePlugin.class.getName());
		tool.addPlugin(ModuleAlgorithmPlugin.class.getName());
		plugin = env.getPlugin(ModuleAlgorithmPlugin.class);
		actions = getActionsByOwner(tool, plugin.getName());
		service = tool.getService(ProgramTreeService.class);

	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testActionsEnabled() throws Exception {
		// set the selection for a Folder
		ProgramModule root = program.getListing().getRootModule("Program Tree");
		GroupPath[] gps = new GroupPath[1];
		gps[0] = new GroupPath(new String[] { root.getName(), ".text" });
		setGroupSelection(gps);

		ViewManagerService vmService = tool.getService(ViewManagerService.class);
		ViewProviderService vps = vmService.getCurrentViewProvider();
		getContextObject(vps);

		for (DockingActionIf action : actions) {
			assertTrue(action.isEnabled());
		}
	}

	@Test
	public void testActiveObject() throws Exception {
		// set the selection for a Folder
		ProgramModule root = program.getListing().getRootModule("Program Tree");
		GroupPath[] gps = new GroupPath[1];
		gps[0] = new GroupPath(new String[] { root.getName(), ".text" });
		setGroupSelection(gps);

		ViewManagerService vmService = tool.getService(ViewManagerService.class);
		ViewProviderService vps = vmService.getCurrentViewProvider();

		getContextObject(vps);

		performAction(CollectionUtils.any(actions), createContext(context), true);

		waitForTasks();
		program.flushEvents();

		assertNotNull(
			program.getListing().getModule("Program Tree", ".text [Subroutine Tree]   [9]"));
	}

	private void setGroupSelection(final GroupPath[] gps) throws Exception {
		runSwing(() -> service.setGroupSelection(gps));

	}

	private void getContextObject(final ViewProviderService vps) throws Exception {

		context = runSwing(() -> context = vps.getActivePopupObject(null));
		assertNotNull(context);
	}

}
