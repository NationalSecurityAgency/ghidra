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

import org.junit.*;

import generic.test.AbstractGTest;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.test.*;

/**
 * The following tests are performed in this test driver for
 * the new front end:
 * (1) connect two running tools by one or more specified events
 * (2) disconnect one or more specified events between two connected tools
 */
public class ChangeToolDataTest extends AbstractGhidraHeadedIntegrationTest {

	private final static String DIRECTORY_NAME = AbstractGTest.getTestDirectoryPath();
	private final static String DATA_NAME_1 = "TestData1";
	private final static String DATA_NAME_2 = "TestData2";

	private Project project;

	@Before
	public void setUp() throws Exception {
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_NAME);
		project = ProjectTestUtils.getProject(DIRECTORY_NAME, PROJECT_NAME);
	}

	@After
	public void tearDown() throws Exception {
		project.close();
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_NAME);
	}

	/*
	 * Tests the following requirements:
	 * (1) connect two running tools by one or more specified events
	 * (2) disconnect one or more specified events between two connected tools
	 * @param args same as args to main()
	 * @param args[0] toolName1
	 * @param args[1] toolName2
	 */
	@Test
	public void testChangeToolData() throws Exception {

		DomainFile[] data = null;

		//
		// setup the running tool
		//
		PluginTool runningTool = new DummyTool();

		//
		// TEST 1: set the data for a tool running without data
		//
		data = new DomainFile[] {
			new ProgramBuilder(DATA_NAME_1, ProgramBuilder._TOY).getProgram().getDomainFile() };

		if (!runningTool.acceptDomainFiles(data)) {
			Assert.fail("FAILED ChangeToolData Without Data");
		}

		//
		// TEST 2: set the data for a tool already running with data
		//
		// verify a confirm prompt is displayed since we will need to save the state of current tool
		//
		data = new DomainFile[] {
			new ProgramBuilder(DATA_NAME_2, ProgramBuilder._TOY).getProgram().getDomainFile() };
		if (!runningTool.acceptDomainFiles(data)) {
			Assert.fail("FAILED ChangeToolData With Data");
		}

	}

}
