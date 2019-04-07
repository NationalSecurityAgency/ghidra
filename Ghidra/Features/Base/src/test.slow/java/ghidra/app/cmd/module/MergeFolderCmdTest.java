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
package ghidra.app.cmd.module;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

/**
 * Test for the merge folder command.
 * 
 * 
 */
public class MergeFolderCmdTest extends AbstractGhidraHeadedIntegrationTest {

	private Program program;

	/**
	 * Sets up the fixture, for example, open a network connection.
	 * This method is called before a test is executed.
	 */
	@Before
	public void setUp() throws Exception {
		program = buildProgram();
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory("test1", "0x1001000", 0x2000);
		builder.createProgramTree("Main Tree");
		builder.createFragment("Main Tree", "A", "a", "0x1001000", "0x1001009");
		builder.createFragment("Main Tree", "A", "b", "0x1001010", "0x1001019");
		builder.createFragment("Main Tree", "A", "c", "0x1001020", "0x1001029");
		builder.createFragment("Main Tree", "A.B", "d", "0x1001030", "0x1001039");
		builder.createFragment("Main Tree", "A.B", "e", "0x1001040", "0x1001049");
		builder.createFragment("Main Tree", "A.B", "f", "0x1001050", "0x1001059");
		return builder.getProgram();
	}

	@Test
    public void testMergeWithParentFolderCmd() throws Exception {

		MergeFolderCmd cmd = new MergeFolderCmd("Main Tree", "B", "A");

		ProgramModule module = program.getListing().getModule("Main Tree", "A");
		Group[] groups = module.getChildren();
		assertEquals(4, groups.length);
		applyCmd(program, cmd);

		module = program.getListing().getModule("Main Tree", "A");
		groups = module.getChildren();
		assertEquals(6, groups.length);

		assertEquals("a", groups[0].getName());
		assertEquals("b", groups[1].getName());
		assertEquals("c", groups[2].getName());
		assertEquals("d", groups[3].getName());
		assertEquals("e", groups[4].getName());
		assertEquals("f", groups[5].getName());

		assertEquals(1, module.getNumParents());
	}

}
