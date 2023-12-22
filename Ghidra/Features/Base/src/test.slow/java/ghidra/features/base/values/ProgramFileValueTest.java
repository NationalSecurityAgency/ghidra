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
package ghidra.features.base.values;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class ProgramFileValueTest extends AbstractValueIntegrationTest {
	private static final String NAME = "Program";

	@Test
	public void testProgramValueNoDefault() throws Exception {
		values.defineProgram(NAME);

		assertTrue(values.isDefined(NAME));
		assertFalse(values.hasValue(NAME));

		values.setProgram(NAME, programA);
		assertTrue(values.hasValue(NAME));

		assertEquals(programA, values.getProgram(NAME, this, null, true));
	}

	@Test
	public void testSetValue() throws Exception {
		values.defineProgram(NAME);
		values.setProgram(NAME, programA);

		assertTrue(values.isDefined(NAME));
		assertTrue(values.hasValue(NAME));
		assertEquals(programA, values.getProgram(NAME, this, null, true));

		values.setProgram(NAME, programB);
		assertTrue(values.hasValue(NAME));

		assertEquals(programB, values.getProgram(NAME, this, null, true));

		values.setProgram(NAME, null);
		assertFalse(values.hasValue(NAME));
	}

	@Test
	public void testGetAsText() throws Exception {
		ProgramFileValue value = values.defineProgram(NAME);
		assertNull(value.getAsText());

		values.setProgram(NAME, programA);

		assertEquals("/A/A", value.getAsText());
	}

	@Test
	public void testSetAsText() {
		ProgramFileValue v = new ProgramFileValue(NAME);
		assertEquals(programA.getDomainFile(), v.setAsText("/A/A"));
		try {
			v.setAsText(null);
			fail("Expected exception");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
		try {
			v.setAsText("/z/z/t");
			fail("Expected exception");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testNoDefaultValueWithNoDialogInput() throws Exception {
		values.defineProgram(NAME);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertFalse(values.hasValue(NAME));
		assertNull(values.getProgram(NAME, this, null, true));
	}

	@Test
	public void testNoDefaultValueWithDialogInput() throws Exception {
		values.defineProgram(NAME);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setProjectFileOnProjectTree(values.getAbstractValue(NAME), programA.getDomainFile());
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(programA, values.getProgram(NAME, this, null, true));
	}

	@Test
	public void testExistingValueWithNoDialogInput() throws Exception {
		values.defineProgram(NAME);
		values.setProgram(NAME, programA);

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(programA, values.getProgram(NAME, this, null, true));
	}

	@Test
	public void testDefaultValueWithDialogInput() throws Exception {
		values.defineProgram(NAME);
		values.setProgram(NAME, programA);

		showDialogOnSwingWithoutBlocking();
		setProjectFileOnProjectTree(values.getAbstractValue(NAME), programB.getDomainFile());
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(programB, values.getProgram(NAME, this, null, true));
	}

	@Test
	public void testOpenProgramInTool() throws Exception {
		PluginTool tool = env.createDefaultTool();
		ProgramManager programManagerService = tool.getService(ProgramManager.class);
		Program[] allOpenPrograms = programManagerService.getAllOpenPrograms();
		assertEquals(0, allOpenPrograms.length);

		values.defineProgram(NAME);
		showDialogOnSwingWithoutBlocking();
		setProjectFileOnProjectTree(values.getAbstractValue(NAME), programA.getDomainFile());
		pressOk();

		Program p = values.getProgram(NAME, this, tool, true);

		allOpenPrograms = programManagerService.getAllOpenPrograms();
		assertEquals(1, allOpenPrograms.length);
		assertEquals(p, allOpenPrograms[0]);
	}

	@Test
	public void testOpenProgramMutltipleTimes() throws Exception {
		values.defineProgram(NAME);
		assertEquals(1, programA.getConsumerList().size());
		showDialogOnSwingWithoutBlocking();
		setProjectFileOnProjectTree(values.getAbstractValue(NAME), programA.getDomainFile());
		pressOk();

		Program p1 = values.getProgram(NAME, this, null, true);
		assertEquals(2, programA.getConsumerList().size());
		Program p2 = values.getProgram(NAME, this, null, true);
		assertEquals(p1, p2);
		assertEquals(3, programA.getConsumerList().size());
		p1.release(this);
		p2.release(this);
	}
}
