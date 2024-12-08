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

public class ProjectFileValueTest extends AbstractValueIntegrationTest {
	private static final String NAME = "Project File";

	@Test
	public void testProjectFileValueNoDefault() {
		values.defineProjectFile(NAME, null);

		assertTrue(values.isDefined(NAME));
		assertFalse(values.hasValue(NAME));

		values.setProjectFile(NAME, fileA);
		assertTrue(values.hasValue(NAME));

		assertEquals(fileA, values.getProjectFile(NAME));
	}

	@Test
	public void testProjectFileValueWithDefault() {
		values.defineProjectFile(NAME);
		values.setProjectFile(NAME, fileA);

		assertTrue(values.isDefined(NAME));
		assertTrue(values.hasValue(NAME));
		assertEquals(fileA, values.getProjectFile(NAME));

		values.setProjectFile(NAME, fileB);
		assertTrue(values.hasValue(NAME));

		assertEquals(fileB, values.getProjectFile(NAME));

		values.setProjectFile(NAME, null);
		assertFalse(values.hasValue(NAME));
	}

	@Test
	public void testGetAsText() {
		ProjectFileValue value1 = new ProjectFileValue(NAME);
		ProjectFileValue value2 = new ProjectFileValue(NAME);
		value2.setValue(fileA);

		assertNull(value1.getAsText());
		assertEquals("/A/A", value2.getAsText());
	}

	@Test
	public void testSetAsText() {
		ProjectFileValue v = new ProjectFileValue(NAME);
		assertEquals(fileA, v.setAsText("/A/A"));
		try {
			v.setAsText(null);
			fail("Expected exception");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
		try {
			v.setAsText("/zasd/asdfas");
			fail("Expected exception");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testNoDefaultValueWithNoDialogInput() {
		values.defineProjectFile(NAME, null);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertFalse(values.hasValue(NAME));
		assertNull(values.getProjectFile(NAME));
	}

	@Test
	public void testNoDefaultValueWithDialogInput() {
		values.defineProjectFile(NAME, null);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setProjectFileOnProjectTree(values.getAbstractValue(NAME), fileA);
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(fileA, values.getProjectFile(NAME));
	}

	@Test
	public void testDefaultValueWithNoDialogInput() {
		values.defineProjectFile(NAME);
		values.setProjectFile(NAME, fileA);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(fileA, values.getProjectFile(NAME));
	}

	@Test
	public void testDefaultValueWithDialogInput() {
		values.defineProjectFile(NAME);
		values.setProjectFile(NAME, fileA);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setProjectFileOnProjectTree(values.getAbstractValue(NAME), fileB);
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(fileB, values.getProjectFile(NAME));
	}

}
