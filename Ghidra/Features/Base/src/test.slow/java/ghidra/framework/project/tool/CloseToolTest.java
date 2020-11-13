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
package ghidra.framework.project.tool;

import static org.junit.Assert.*;

import java.awt.Window;

import org.junit.*;

import docking.action.DockingActionIf;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * test for creating a new empty tool with the new front end
 */
public class CloseToolTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
		closeAllWindows();
	}

	@Test
	public void testCloseToolWithNoData() {
		// launch a tool with the program
		PluginTool tool = env.launchDefaultTool();

		// close tool
		assertNotNull(tool.getToolFrame());
		closeTool(tool);
		assertNull("Tool did not close after task", tool.getToolFrame());

	}

	@Test
	public void testCloseOthersInTool() throws Exception {
		PluginTool tool = env.getTool();
		ProgramManagerPlugin pm = getPlugin(tool, ProgramManagerPlugin.class);

		// launch a tool with the program
		tool = env.launchDefaultTool();

		ProgramDB program1 = new ProgramBuilder("DiffTestPgm2", ProgramBuilder._TOY).getProgram();
		ProgramDB program2 =
			new ProgramBuilder("WinHelloCPP.exe", ProgramBuilder._TOY).getProgram();
		ProgramDB program3 = new ProgramBuilder("DiffTestPgm1", ProgramBuilder._TOY).getProgram();
		pm.openProgram(program1, true);
		pm.openProgram(program2, true);
		pm.openProgram(program3, true);
		Program[] allOpenPrograms = pm.getAllOpenPrograms();
		assertEquals(3, allOpenPrograms.length);

		DockingActionIf closeOthersAction = getAction(pm, "Close Others");
		assertNotNull(closeOthersAction);
		assertEquals(true, closeOthersAction.isEnabled());
		performAction(closeOthersAction, true);

		allOpenPrograms = pm.getAllOpenPrograms();
		assertEquals(1, allOpenPrograms.length);
		assertEquals(program3, allOpenPrograms[0]);

		// close tool
		assertNotNull(tool.getToolFrame());
		closeTool(tool);
		assertNull("Tool did not close after task", tool.getToolFrame());

	}

	@Test
	public void testCloseToolWithOpenProgram() throws Exception {
		// open a program
		ProgramDB program = new ProgramBuilder("notepad", ProgramBuilder._TOY).getProgram();

		// launch a tool with the program
		PluginTool tool = env.launchDefaultTool(program);

		// close tool
		assertNotNull(tool.getToolFrame());
		closeTool(tool);
		assertNull("Tool did not close after task", tool.getToolFrame());

	}

	@Test
	public void testCannotCloseToolWithBackgroundTaskRunning() throws Exception {
		// open a program
		ProgramDB program = new ProgramBuilder("notepad", ProgramBuilder._TOY).getProgram();

		// launch a tool with the program
		PluginTool tool = env.launchDefaultTool(program);

		// start a background task that will run until we tell it to finish.
		ControllableBackgroundCommand cmd = new ControllableBackgroundCommand();
		tool.executeBackgroundCommand(cmd, program);
		waitForCommandToStart(cmd);

		// try to close the tool
		closeTool(tool);

		// check for warning dialog
		Window window = waitForWindow("Tool Busy");
		assertNotNull("Did not get tool busy dialog", window);
		closeWindow(window);

		// try to close the program
		closeProgram(tool, program);

		// check for warning dialog
		window = waitForWindow("Close notepad Failed");
		assertNotNull("Did not get \"close failed\" dialog", window);
		closeWindow(window);

		// stop background task
		stopBackgroundCommand(tool, cmd);

		// close tool
		assertNotNull(tool.getToolFrame());
		closeTool(tool);
		assertNull("Tool did not close after task", tool.getToolFrame());
	}

	private void closeWindow(final Window window) {
		runSwing(() -> window.dispose());
	}

	private void stopBackgroundCommand(PluginTool tool, ControllableBackgroundCommand cmd) {
		cmd.stop = true;
		waitForBusyTool(tool);
	}

	private void closeProgram(final PluginTool tool, final ProgramDB program) {

		DockingActionIf action = getAction(tool, "ProgramManagerPlugin", "Close File");
		performAction(action, new ProgramActionContext(null, program), false);

		waitForPostedSwingRunnables();
	}

	private void waitForCommandToStart(ControllableBackgroundCommand cmd) {
		int numWaits = 0;
		while (!cmd.hasStarted && numWaits < 50) {
			numWaits++;
			sleep(50);
		}
		assertTrue(cmd.hasStarted);
	}

	private void closeTool(final PluginTool tool) {
		executeOnSwingWithoutBlocking(() -> tool.close());
		waitForPostedSwingRunnables();
	}

//==================================================================================================
// Inner Classes	
//==================================================================================================	

	private class ControllableBackgroundCommand extends BackgroundCommand {

		private volatile boolean hasStarted;
		private volatile boolean stop;

		public ControllableBackgroundCommand() {
			super("Test Background Command", false, true, false);
			setStatusMsg("Running controllable background command...");
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			hasStarted = true;

			while (!stop) {
				sleep(100);
			}

			return true;
		}
	}
}
