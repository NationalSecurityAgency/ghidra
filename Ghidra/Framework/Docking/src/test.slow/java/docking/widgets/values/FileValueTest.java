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
package docking.widgets.values;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;

import org.junit.Test;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.values.AbstractValue;
import docking.widgets.values.FileValue;
import docking.widgets.values.FileValue.FileValuePanel;

public class FileValueTest extends AbstractValueTest {
	private static final String NAME = "My File";

	@Test
	public void testFileValueNoDefault() {
		values.defineFile(NAME, null);

		assertTrue(values.isDefined(NAME));
		assertFalse(values.hasValue(NAME));

		values.setFile(NAME, new File("."));
		assertTrue(values.hasValue(NAME));

		assertEquals(new File("."), values.getFile(NAME));
	}

	@Test
	public void testFileValueWithDefault() {
		values.defineFile(NAME, new File("/"));

		assertTrue(values.isDefined(NAME));
		assertTrue(values.hasValue(NAME));
		assertEquals(new File("/"), values.getFile(NAME));

		values.setFile(NAME, new File("."));
		assertTrue(values.hasValue(NAME));

		assertEquals(new File("."), values.getFile(NAME));

		values.setFile(NAME, null);
		assertFalse(values.hasValue(NAME));
	}

	@Test
	public void testGetAsText() {
		FileValue value1 = new FileValue(NAME);
		FileValue value2 = new FileValue(NAME, new File("/"));
		assertNull(value1.getAsText());
		assertEquals("/", value2.getAsText());
	}

	@Test
	public void testSetAsText() {
		FileValue v = new FileValue(NAME);
		assertEquals(new File("/abc"), v.setAsText("/abc"));
		try {
			v.setAsText(null);
			fail("Expected exception");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testDirectoryValueNoDefault() {
		values.defineDirectory(NAME, null);

		assertTrue(values.isDefined(NAME));
		assertFalse(values.hasValue(NAME));

		values.setFile(NAME, new File("."));
		assertTrue(values.hasValue(NAME));

		assertEquals(new File("."), values.getFile(NAME));
	}

	@Test
	public void testDirectoryValueWithDefault() {
		values.defineDirectory(NAME, new File("/"));

		assertTrue(values.isDefined(NAME));
		assertTrue(values.hasValue(NAME));
		assertEquals(new File("/"), values.getFile(NAME));

		values.setFile(NAME, new File("."));
		assertTrue(values.hasValue(NAME));

		assertEquals(new File("."), values.getFile(NAME));

		values.setFile(NAME, null);
		assertFalse(values.hasValue(NAME));
	}

	@Test
	public void testNoDefaultValueWithNoDialogInput() {
		values.defineFile(NAME, null);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertFalse(values.hasValue(NAME));
		assertNull(values.getFile(NAME));
	}

	@Test
	public void testNoDefaultValueWithDialogInput() throws IOException {
		File foo = createTempFile("foo");
		values.defineFile(NAME, null);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setFile(values.getAbstractValue(NAME), foo);
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(foo, values.getFile(NAME));
	}

	@Test
	public void testDefaultValueWithNoDialogInput() {
		values.defineFile(NAME, new File("/"));
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(new File("/"), values.getFile(NAME));
	}

	@Test
	public void testDefaultValueWithDialogInput() throws IOException {
		File foo = createTempFile("foo");
		File bar = createTempFile("bar");
		values.defineFile(NAME, foo);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setFile(values.getAbstractValue(NAME), bar);
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(bar, values.getFile(NAME));
	}

	@Test
	public void testDirectoryWithDialogInput() throws IOException {
		File dir = createTempDirectory("foo");
		values.defineDirectory(NAME, null);
		showDialogOnSwingWithoutBlocking();
		setFile(values.getAbstractValue(NAME), dir);
		pressOk();

		assertEquals(dir, values.getFile(NAME));
	}

	@Test
	public void testStartingDir() throws IOException {
		File file = createTempDirectory("foo");
		File parent = file.getParentFile();
		values.defineFile(NAME, null, parent);
		showDialogOnSwingWithoutBlocking();
		FileValuePanel fileWidget = (FileValuePanel) values.getAbstractValue(NAME).getComponent();
		pressButtonByName(fileWidget, "BrowseButton", false);
		GhidraFileChooser chooser = waitForDialogComponent(GhidraFileChooser.class);
		File dir = runSwing(() -> chooser.getCurrentDirectory());
		pressButtonByText(chooser, "Cancel");
		pressOk();

		assertEquals(parent, dir);
	}

	protected void setFile(AbstractValue<?> nameValue, File f) {
		FileValuePanel fileWidget = (FileValuePanel) nameValue.getComponent();
		pressButtonByName(fileWidget, "BrowseButton", false);
		GhidraFileChooser chooser = waitForDialogComponent(GhidraFileChooser.class);
		runSwing(() -> {
			chooser.setSelectedFile(f);
		});

		pressButtonByText(chooser, "OK");
	}
}
