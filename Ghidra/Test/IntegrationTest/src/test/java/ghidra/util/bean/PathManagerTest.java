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
package ghidra.util.bean;

import static org.junit.Assert.*;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import org.junit.*;

import docking.test.AbstractDockingTest;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.pathmanager.PathManager;
import docking.widgets.pathmanager.PathManagerListener;
import docking.widgets.table.GTable;
import generic.util.Path;
import ghidra.framework.preferences.Preferences;
import ghidra.util.filechooser.ExtensionFileFilter;
import resources.ResourceManager;

public class PathManagerTest extends AbstractDockingTest {

	private PathManager pathManager;
	private GTable table;
	private JFrame frame;
	private boolean wasListenerNotified = false;

	@Before
	public void setUp() throws Exception {
		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		List<Path> paths = new ArrayList<>();
		paths.add(new Path(new File("c:\\path_one")));
		paths.add(new Path(new File("c:\\path_two")));
		paths.add(new Path(new File("c:\\path_three")));
		paths.add(new Path(new File("c:\\path_four")));
		paths.add(new Path(new File("c:\\path_four")));

		runSwing(() -> {
			pathManager = new PathManager(paths, true, true);
			table = (GTable) findComponentByName(pathManager.getComponent(), "PATH_TABLE");
			frame = new JFrame("Test");
			frame.getContentPane().add(pathManager.getComponent());
			frame.pack();
		});
		frame.setVisible(true);
	}

	@After
	public void tearDown() throws Exception {
		frame.setVisible(false);
		wasListenerNotified = false;
	}

	@Test
	public void testUpArrow() throws Exception {
		selectRow(3);
		JButton upButton = findButtonByIcon(pathManager.getComponent(),
			ResourceManager.loadImage("images/up.png"));
		assertNotNull(upButton);
		pressButton(upButton, true);
		waitForSwing();

		int row = table.getSelectedRow();
		assertEquals(2, row);
		assertEquals(new Path("c:\\path_four"), table.getModel().getValueAt(row, 1));

		pressButton(upButton, true);
		waitForSwing();
		row = table.getSelectedRow();
		assertEquals(1, row);
		assertEquals(new Path("c:\\path_four"), table.getModel().getValueAt(row, 1));

		pressButton(upButton, true);
		waitForSwing();
		row = table.getSelectedRow();
		assertEquals(0, row);
		assertEquals(new Path("c:\\path_four"), table.getModel().getValueAt(row, 1));

		pressButton(upButton, true);
		waitForSwing();
		row = table.getSelectedRow();
		assertEquals(3, row);
		assertEquals(new Path("c:\\path_four"), table.getModel().getValueAt(row, 1));
	}

	@Test
	public void testDownArrow() throws Exception {
		selectRow(2);

		JButton downButton = findButtonByIcon(pathManager.getComponent(),
			ResourceManager.loadImage("images/down.png"));
		assertNotNull(downButton);
		pressButton(downButton, true);
		waitForSwing();

		int row = table.getSelectedRow();
		assertEquals(3, row);
		assertEquals(new Path("c:\\path_three"), table.getModel().getValueAt(row, 1));

		pressButton(downButton, true);
		waitForSwing();
		row = table.getSelectedRow();
		assertEquals(0, row);
		assertEquals(new Path("c:\\path_three"), table.getModel().getValueAt(row, 1));

		pressButton(downButton, true);
		waitForSwing();
		row = table.getSelectedRow();
		assertEquals(1, row);
		assertEquals(new Path("c:\\path_three"), table.getModel().getValueAt(row, 1));

		pressButton(downButton, true);
		waitForSwing();
		row = table.getSelectedRow();
		assertEquals(2, row);
		assertEquals(new Path("c:\\path_three"), table.getModel().getValueAt(row, 1));
	}

	@Test
	public void testRemove() throws Exception {
		selectRow(3);

		JButton button = findButtonByIcon(pathManager.getComponent(),
			ResourceManager.loadImage("images/edit-delete.png"));
		assertNotNull(button);
		pressButton(button, true);
		waitForSwing();
		int row = table.getSelectedRow();
		assertEquals(2, row);

		pressButton(button, true);
		waitForSwing();
		row = table.getSelectedRow();
		assertEquals(1, row);

		pressButton(button, true);
		waitForSwing();
		row = table.getSelectedRow();
		assertEquals(0, row);

		pressButton(button, true);
		waitForSwing();
		row = table.getSelectedRow();
		assertEquals(-1, row);

		assertTrue(!button.isEnabled());
	}

	@Test
	public void testAddButton() throws Exception {

		PathManagerListener listener = new PathManagerListener() {
			@Override
			public void pathsChanged() {
				wasListenerNotified = true;
			}

			@Override
			public void pathMessage(String message) {
				// don't care
			}
		};

		pathManager.addListener(listener);

		File temp = createTempFileForTest();

		Preferences.setProperty(Preferences.LAST_IMPORT_DIRECTORY, temp.getParent());
		pathManager.setFileChooserProperties("Select Source Files",
			Preferences.LAST_IMPORT_DIRECTORY, GhidraFileChooserMode.FILES_AND_DIRECTORIES, true,
			new ExtensionFileFilter(new String[] { "h" }, "C Header Files"));

		JButton button = findButtonByIcon(pathManager.getComponent(),
			ResourceManager.loadImage("images/Plus.png"));
		assertNotNull(button);
		pressButton(button, false);

		waitForSwing();
		GhidraFileChooser fileChooser = waitForDialogComponent(GhidraFileChooser.class);
		assertNotNull(fileChooser);

		JButton chooseButton = findButtonByText(fileChooser, "OK");
		assertNotNull(chooseButton);

		runSwing(() -> fileChooser.setSelectedFile(new File(temp.getParent(), "fred.h")));
		waitForUpdateOnChooser(fileChooser);

		pressButton(chooseButton);
		assertTrue("The file chooser did not close as expected", !fileChooser.isVisible());
		waitForSwing();

		assertEquals(5, table.getRowCount());

		Path filename = (Path) table.getModel().getValueAt(0, 1);
		assertTrue(filename.getPathAsString().endsWith("fred.h"));

		assertTrue(wasListenerNotified);
		pathManager.removeListener(listener);
	}

	@Test
	public void testCancelAdd() throws Exception {

		File temp = createTempFileForTest();

		Preferences.setProperty(Preferences.LAST_IMPORT_DIRECTORY, temp.getParent());
		pathManager.setFileChooserProperties("Select Source Files",
			Preferences.LAST_IMPORT_DIRECTORY, GhidraFileChooserMode.FILES_AND_DIRECTORIES, true,
			new ExtensionFileFilter(new String[] { "h" }, "C Header Files"));

		JButton button = findButtonByIcon(pathManager.getComponent(),
			ResourceManager.loadImage("images/Plus.png"));
		assertNotNull(button);
		pressButton(button, false);

		waitForSwing();
		GhidraFileChooser fileChooser = waitForDialogComponent(GhidraFileChooser.class);
		assertNotNull(fileChooser);

		assertEquals(temp.getParentFile().getName(), fileChooser.getCurrentDirectory().getName());
		assertTrue(fileChooser.isMultiSelectionEnabled());

		File f = new File("c:\\temp\\myInclude.h");
		assertTrue(fileChooser.accept(f));
		f = new File("c:\\temp\\myFile.c");
		assertTrue(!fileChooser.accept(f));

		pressButtonByText(fileChooser, "Cancel", true);
	}

	@Test
	public void testClear() throws Exception {
		runSwing(() -> pathManager.clear());
		assertEquals(0, table.getRowCount());
	}

	private void selectRow(final int row) throws Exception {
		runSwing(() -> table.setRowSelectionInterval(row, row));
	}

	@Test
	public void testPathPreferenceRetention() {

		Preferences.setProperty("ENABLED_PATHS", null);
		Preferences.setProperty("DISABLED_PATHS", null);

		Path[] defaultPaths = new Path[] {
			new Path("/foo"), new Path("/bar")
		};

		Path[] restoredPaths =
			PathManager.getPathsFromPreferences("ENABLED_PATHS", defaultPaths, "DISABLED_PATHS");
		assertArrayEquals(defaultPaths, restoredPaths);

		Path[] paths = new Path[] {
			new Path("/jim", false), new Path("/joe", false), new Path("/bob", true),
			new Path("/sam", false), new Path("/tom", true), new Path("/tim", false)
		};
		PathManager.savePathsToPreferences("ENABLED_PATHS", "DISABLED_PATHS", paths);

		restoredPaths =
			PathManager.getPathsFromPreferences("ENABLED_PATHS", defaultPaths, "DISABLED_PATHS");
		assertArrayEquals(paths, restoredPaths);
	}

}
