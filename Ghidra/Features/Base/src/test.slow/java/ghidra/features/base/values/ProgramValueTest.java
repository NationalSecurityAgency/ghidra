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
import ghidra.features.base.values.ProgramValue;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class ProgramValueTest extends AbstractValueIntegrationTest {
	private static final String NAME = "Program";

	@Test
	public void testProgramValueNoDefault() {
		values.defineProgram(NAME, this, null);

		assertTrue(values.isDefined(NAME));
		assertFalse(values.hasValue(NAME));

		values.setProgram(NAME, programA);
		assertTrue(values.hasValue(NAME));

		assertEquals(programA, values.getProgram(NAME));
	}

	@Test
	public void testProgramValueWithDefault() {
		values.defineProgram(NAME, programA, this, null);

		assertTrue(values.isDefined(NAME));
		assertTrue(values.hasValue(NAME));
		assertEquals(programA, values.getProgram(NAME));

		values.setProgram(NAME, programB);
		assertTrue(values.hasValue(NAME));

		assertEquals(programB, values.getProgram(NAME));

		values.setProgram(NAME, null);
		assertFalse(values.hasValue(NAME));
	}

	@Test
	public void testGetAsText() {
		ProgramValue value1 = new ProgramValue(NAME, this, null);
		ProgramValue value2 = new ProgramValue(NAME, programA, this, null);
		assertNull(value1.getAsText());
		assertEquals("/A/A", value2.getAsText());
	}

	@Test
	public void testSetAsText() {
		ProgramValue v = new ProgramValue(NAME, this, null);
		assertEquals(programA, v.setAsText("/A/A"));
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
	public void testNoDefaultValueWithNoDialogInput() {
		values.defineProgram(NAME, this, null);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertFalse(values.hasValue(NAME));
		assertNull(values.getProgram(NAME));
	}

	@Test
	public void testNoDefaultValueWithDialogInput() {
		values.defineProgram(NAME, this, null);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setProjectFileOnProjectTree(values.getAbstractValue(NAME), programA.getDomainFile());
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(programA, values.getProgram(NAME));
	}

	@Test
	public void testDefaultValueWithNoDialogInput() {
		values.defineProgram(NAME, programA, this, null);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(programA, values.getProgram(NAME));
	}

	@Test
	public void testDefaultValueWithDialogInput() {
		values.defineProgram(NAME, programA, this, null);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setProjectFileOnProjectTree(values.getAbstractValue(NAME), programB.getDomainFile());
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(programB, values.getProgram(NAME));
	}

	@Test
	public void testOpenProgramInTool() {
		PluginTool tool = env.createDefaultTool();
		ProgramManager programManagerService = tool.getService(ProgramManager.class);
		Program[] allOpenPrograms = programManagerService.getAllOpenPrograms();
		assertEquals(0, allOpenPrograms.length);

		values.defineProgram(NAME, this, tool);
		showDialogOnSwingWithoutBlocking();
		setProjectFileOnProjectTree(values.getAbstractValue(NAME), programA.getDomainFile());
		pressOk();

		allOpenPrograms = programManagerService.getAllOpenPrograms();
		assertEquals(1, allOpenPrograms.length);
		assertEquals(programA, allOpenPrograms[0]);
	}

}
