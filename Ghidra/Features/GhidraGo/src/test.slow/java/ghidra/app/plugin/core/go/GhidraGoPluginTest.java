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
package ghidra.app.plugin.core.go;

import static org.junit.Assert.*;

import java.net.URL;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Predicate;

import org.junit.*;

import docking.AbstractErrDialog;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraGo;
import ghidra.app.plugin.core.go.ipc.CheckForFileProcessedRunnable;
import ghidra.app.plugin.core.go.ipc.CheckForListenerRunnable;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.Program;
import ghidra.test.*;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

public class GhidraGoPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private final static String DIRECTORY_NAME = getTestDirectoryPath();
	private final static String ACTIVE_PROJECT = "active";
	private final static String INACTIVE_PROJECT = "inactive";
	private TestEnv env;
	private PluginTool tool;
	private GhidraGo ghidraGo;
	private Project inactiveProject;

	private GhidraApplicationLayout layout;

	@Before
	public void setUp() throws Exception {

		// clean up projects
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, ACTIVE_PROJECT);
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, INACTIVE_PROJECT);

		// create inactive project if it doesn't exist
		ProjectTestUtils.getProject(DIRECTORY_NAME, INACTIVE_PROJECT).close();

		// add program and folder to inactive project
		inactiveProject = ProjectTestUtils.getProject(DIRECTORY_NAME, INACTIVE_PROJECT);
		addProgramAndFolderToProject(inactiveProject);
		inactiveProject.close();

		// set up test env and add GhidraGoPlugin to the front end tool.
		env = new TestEnv(ACTIVE_PROJECT);
		tool = env.getFrontEndTool();
		tool.addPlugin(GhidraGoPlugin.class.getName());
		showTool(tool);
		layout = (GhidraApplicationLayout) createApplicationLayout();
		addProgramAndFolderToProject(env.getProject());

		// initialize GhidraGo client
		ghidraGo = new GhidraGo();

		CheckForFileProcessedRunnable.WAIT_FOR_PROCESSING_DELAY_MS = 1000;
		CheckForFileProcessedRunnable.MAX_WAIT_FOR_PROCESSING_MIN = 1;
		CheckForFileProcessedRunnable.WAIT_FOR_PROCESSING_PERIOD_MS = 10;

		CheckForListenerRunnable.WAIT_FOR_LISTENER_DELAY_MS = 1000;
		CheckForListenerRunnable.MAX_WAIT_FOR_LISTENER_MIN = 1;
		CheckForListenerRunnable.WAIT_FOR_LISTENER_PERIOD_MS = 10;
	}

	private void addProgramAndFolderToProject(Project p) throws Exception {
		Program program = createNotepadProgram();
		DomainFolder rootFolder = p.getProjectData().getRootFolder();
		rootFolder.createFile("notepad", program, TaskMonitor.DUMMY);
		rootFolder.createFolder("testFolder");

	}

	private Program createNotepadProgram() throws Exception {
		ClassicSampleX86ProgramBuilder builder =
			new ClassicSampleX86ProgramBuilder("notepad", false, this);

		return builder.getProgram();
	}

	@After
	public void tearDown() {
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, ACTIVE_PROJECT);
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, INACTIVE_PROJECT);
		env.dispose();
	}

	@Test
	public void testLaunchingWithProgramUrl() throws Exception {
		// given a valid local GhidraURL pointing to a program
		URL url = GhidraURL.makeURL(env.getProjectManager().getActiveProject().getProjectLocator(),
			"/notepad", null);

		// when ghidraGo is launched with the url
		Swing.runLater(() -> {
			try {
				ghidraGo.launch(layout, new String[] { url.toString() });
			}
			catch (Exception e) {
				// empty
			}
		});

		// then the code browser should be launched
		waitForSwing();
		waitFor(() -> Arrays.asList(tool.getToolServices().getRunningTools())
				.stream()
				.map(PluginTool::getName)
				.anyMatch(Predicate.isEqual("CodeBrowser")));
		Optional<PluginTool> cb = Arrays.asList(tool.getToolServices().getRunningTools())
				.stream()
				.filter(p -> p.getName().equals("CodeBrowser"))
				.findFirst();
		assertTrue(cb.isPresent());

		// and the domain file should be open in the code browser
		assertTrue(Arrays.asList(cb.get().getDomainFiles())
				.stream()
				.map(DomainFile::getName)
				.anyMatch(Predicate.isEqual("notepad")));
	}

	@Test
	public void testLaunchingWithProgramUrlForInactiveProject() throws Exception {
		// given a valid local GhidraURL pointing to a program contained within the inactive project
		URL url = GhidraURL.makeURL(inactiveProject.getProjectLocator(), "/notepad", null);

		try {
			// when ghidraGo is launched with the url
			Swing.runLater(() -> {
				try {
					ghidraGo.launch(layout, new String[] { url.toString() });
				}
				catch (Exception e) {
					// empty
				}
			});

			// then the code browser should be launched
			waitForSwing();
			waitFor(() -> Arrays.asList(tool.getToolServices().getRunningTools())
					.stream()
					.map(PluginTool::getName)
					.anyMatch(Predicate.isEqual("CodeBrowser")));
			Optional<PluginTool> cb = Arrays.asList(tool.getToolServices().getRunningTools())
					.stream()
					.filter(p -> p.getName().equals("CodeBrowser"))
					.findFirst();
			assertTrue(cb.isPresent());

			// and the domain file should be open in the code browser
			assertTrue(Arrays.asList(cb.get().getDomainFiles())
					.stream()
					.map(DomainFile::getName)
					.anyMatch(Predicate.isEqual("notepad")));
		}
		finally {
			inactiveProject.close();
		}

	}

	@Test
	public void testLaunchingWithFolderUrl() throws Exception {
		// given a valid local GhidraURL pointing to a folder within the active project
		URL url = GhidraURL.makeURL(env.getProjectManager().getActiveProject().getProjectLocator(),
			"/testFolder", null);

		// when ghidraGo is launched with the url
		Swing.runLater(() -> {
			try {
				ghidraGo.launch(layout, new String[] { url.toString() });
			}
			catch (Exception e) {
				// empty
			}
		});

		// then the project window should select the folder within the active project data panel
		waitForSwing();

		ProjectLocator[] projViews = env.getProject().getProjectViews();
		Assert.assertEquals(0, projViews.length);
	}

	@Test
	public void testLaunchingWithFolderUrlForInactiveProject() throws Exception {
		// given a valid local GhidraURL pointing to a folder within an in-active project
		URL url =
			GhidraURL.makeURL(inactiveProject.getProjectLocator(),
				"/testFolder", null);

		try {
			// when ghidraGo is launched with the url
			Swing.runLater(() -> {
				try {
					ghidraGo.launch(layout, new String[] { url.toString() });
				}
				catch (Exception e) {
					// empty
				}
			});

			// then the project window should select the folder within the viewed project data panel
			waitForSwing();
			ProjectLocator[] projViews = env.getProject().getProjectViews();
			Assert.assertEquals(1, projViews.length);
		}
		finally {
			inactiveProject.close();
		}

	}

	@Test
	public void testLaunchingWithResourceThatDoesNotExist() throws Exception {
		// given a valid local GhidraURL pointing to a program that does not exist
		URL url = GhidraURL.makeURL(env.getProjectManager().getActiveProject().getProjectLocator(),
			"/test", null);

		// when ghidraGo is launched with the url
		Swing.runLater(() -> {
			try {
				ghidraGo.launch(layout, new String[] { url.toString() });
			}
			catch (Exception e) {
				// empty
			}
		});

		// then an error dialog should be displayed
		AbstractErrDialog err = waitForErrorDialog();
		assertEquals("Content Not Found", err.getTitle());
	}

}
