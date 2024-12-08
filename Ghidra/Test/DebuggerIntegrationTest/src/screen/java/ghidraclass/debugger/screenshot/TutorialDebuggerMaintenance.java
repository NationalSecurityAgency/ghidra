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
package ghidraclass.debugger.screenshot;

import java.io.File;

import org.junit.*;

import db.Transaction;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class TutorialDebuggerMaintenance extends AbstractGhidraHeadedIntegrationTest {
	public static final TaskMonitor CONSOLE = new ConsoleTaskMonitor();

	public PluginTool tool;
	public TestEnv env;
	public Program program;

	@Before
	public void setUp() throws Throwable {
		env = new TestEnv();

		tool = env.launchDefaultTool();
	}

	@After
	public void tearDown() throws Throwable {
		if (program != null) {
			program.release(this);
			program = null;
		}
	}

	@Test
	public void testRecreateTermminesGzf() throws Throwable {
		File termmines = Application.getModuleDataFile("TestResources", "termmines").getFile(false);
		LoadResults<Program> results = AutoImporter.importByUsingBestGuess(termmines,
			env.getProject(), "/", this, new MessageLog(), CONSOLE);
		program = results.getPrimaryDomainObject();
		try (Transaction tx = program.openTransaction("Analyze")) {
			program.setExecutablePath("/tmp/termmines");
			GhidraProject.analyze(program);
		}
		File dest = new File(termmines.getParentFile(), "termmines.gzf");
		dest.delete();
		program.saveToPackedFile(dest, CONSOLE);
	}
}
