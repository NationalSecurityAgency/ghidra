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
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.Program;
import ghidra.test.*;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

public class GhidraGoPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private GhidraGo ghidraGo;
	private URL url;

	private GhidraApplicationLayout layout;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		tool = env.getFrontEndTool();
		tool.addPlugin(GhidraGoPlugin.class.getName());
		showTool(tool);

		DomainFolder rootFolder = env.getProject().getProjectData().getRootFolder();

		Program p = createNotepadProgram();

		rootFolder.createFile("notepad", p, TaskMonitor.DUMMY);

		env.release(p);

		url = GhidraURL.makeURL(env.getProjectManager().getActiveProject().getProjectLocator(),
			"/notepad", null);

		layout = (GhidraApplicationLayout) createApplicationLayout();
		ghidraGo = new GhidraGo();


		CheckForFileProcessedRunnable.WAIT_FOR_PROCESSING_DELAY_MS = 1000;
		CheckForFileProcessedRunnable.MAX_WAIT_FOR_PROCESSING_MIN = 1;
		CheckForFileProcessedRunnable.WAIT_FOR_PROCESSING_PERIOD_MS = 10;

		CheckForListenerRunnable.WAIT_FOR_LISTENER_DELAY_MS = 1000;
		CheckForListenerRunnable.MAX_WAIT_FOR_LISTENER_MIN = 1;
		CheckForListenerRunnable.WAIT_FOR_LISTENER_PERIOD_MS = 10;
	}

	private Program createNotepadProgram() throws Exception {
		ClassicSampleX86ProgramBuilder builder =
			new ClassicSampleX86ProgramBuilder("notepad", false, this);

		return builder.getProgram();
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testProcessingUrl() throws Exception {
		Swing.runLater(() -> {
			try {
				ghidraGo.launch(layout, new String[] { url.toString() });
			}
			catch (Exception e) {
				// empty
			}
		});
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
		assertTrue(Arrays.asList(cb.get().getDomainFiles())
				.stream()
				.map(DomainFile::getName)
				.anyMatch(Predicate.isEqual("notepad")));
	}

	@Test
	public void testLaunchingWithInvalidUrl() throws Exception {
		Swing.runLater(() -> {
			try {
				ghidraGo.launch(layout, new String[] { "ghidra:/test" });
			}
			catch (Exception e) {
				// empty
			}
		});
		AbstractErrDialog err = waitForErrorDialog();
		assertEquals("Unsupported Content", err.getTitle());
	}

}
