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
package ghidra.app.plugin.core.progmgr;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.*;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ProgramCachingServiceTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private Project project;
	private DomainFolder rootFolder;
	private DomainFile domainFile;
	private PluginTool tool;
	private ProgramManager service;

	@Before
	public void setup() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		project = env.getProject();
		rootFolder = project.getProjectData().getRootFolder();
		ProgramBuilder builder = new ProgramBuilder("A", ProgramBuilder._TOY, this);
		Program program = builder.getProgram();
		domainFile = rootFolder.createFile("A", program, TaskMonitor.DUMMY);
		service = tool.getService(ProgramManager.class);
		program.release(this);
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testCacheProgram() {
		Object consumer1 = new Object();
		Object consumer2 = new Object();
		Program program1 = service.openCachedProgram(domainFile, consumer1);
		assertEquals(2, program1.getConsumerList().size()); // one we added and one by the cache

		program1.release(consumer1);
		assertEquals(1, program1.getConsumerList().size()); // just the cache

		Program program2 = service.openCachedProgram(domainFile, consumer2);
		assertTrue(program1 == program2);
		assertEquals(2, program2.getConsumerList().size()); // consumer2 and the cache

	}

	@Test
	public void testSaveAs() throws InvalidNameException, CancelledException, IOException {
		Object consumer1 = new Object();
		Object consumer2 = new Object();
		Program program = service.openCachedProgram(domainFile, consumer1);
		assertEquals(2, program.getConsumerList().size()); // consumer1 and the cache
		assertTrue(program.getConsumerList().contains(consumer1));

		rootFolder.createFile("B", program, TaskMonitor.DUMMY);	// doing 'Save As'
		assertEquals(1, program.getConsumerList().size());   // cache should have removed it, so just consumer1
		assertTrue(program.getConsumerList().contains(consumer1));

		Program other = service.openCachedProgram(domainFile, consumer2);
		assertTrue(program != other);
		assertEquals(2, other.getConsumerList().size());   // cache and consumer 2
		assertTrue(other.getConsumerList().contains(consumer2));
		assertFalse(other.getConsumerList().contains(consumer1));

	}

}
