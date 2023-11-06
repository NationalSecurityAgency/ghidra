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

public class ProjectFolderValueTest extends AbstractValueIntegrationTest {
	private static final String NAME = "Project File";

	@Test
	public void testProjectFolderValueNoDefault() {
		values.defineProjectFolder(NAME, null);

		assertTrue(values.isDefined(NAME));
		assertFalse(values.hasValue(NAME));

		values.setProjectFolder(NAME, folderA);
		assertTrue(values.hasValue(NAME));

		assertEquals(folderA, values.getProjectFolder(NAME));
	}

	@Test
	public void testProjectFolderValueWithDefault() {
		values.defineProjectFolder(NAME, "/A");

		assertTrue(values.isDefined(NAME));
		assertTrue(values.hasValue(NAME));
		assertEquals(folderA, values.getProjectFolder(NAME));

		values.setProjectFolder(NAME, folderB);
		assertTrue(values.hasValue(NAME));

		assertEquals(folderB, values.getProjectFolder(NAME));

		values.setProjectFolder(NAME, null);
		assertFalse(values.hasValue(NAME));
	}

	@Test
	public void testGetAsText() {
		ProjectFolderValue value1 = new ProjectFolderValue(NAME);
		ProjectFolderValue value2 = new ProjectFolderValue(NAME, "/A");
		assertNull(value1.getAsText());
		assertEquals("/A", value2.getAsText());
	}

	@Test
	public void testSetAsText() {
		ProjectFolderValue v = new ProjectFolderValue(NAME);
		assertEquals(folderA, v.setAsText("/A"));
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
		values.defineProjectFolder(NAME);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		// usually, this would have no value, but the root folder is such an obvious value
		// in nothing is entered, we use that.
		assertTrue(values.hasValue(NAME));
		assertEquals(rootFolder, values.getProjectFolder(NAME));
	}

	@Test
	public void testNoDefaultValueWithDialogInput() {
		values.defineProjectFolder(NAME);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setProjectFolderOnProjectTree(values.getAbstractValue(NAME), folderA);
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(folderA, values.getProjectFolder(NAME));
	}

	@Test
	public void testDefaultValueWithNoDialogInput() {
		values.defineProjectFolder(NAME, "/A");
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(folderA, values.getProjectFolder(NAME));
	}

	@Test
	public void testDefaultValueWithDialogInput() {
		values.defineProjectFolder(NAME, "/A");
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setProjectFolderOnProjectTree(values.getAbstractValue(NAME), folderB);
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(folderB, values.getProjectFolder(NAME));
	}

}
