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

import javax.swing.*;

import org.junit.*;

import docking.test.AbstractDockingTest;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.pathmanager.PathnameTablePanel;
import ghidra.app.util.importer.LibrarySearchPathManager;
import ghidra.framework.preferences.Preferences;
import ghidra.util.filechooser.ExtensionFileFilter;
import resources.ResourceManager;

/**
 * 
 * 
 *
 */
public class PathnameTablePanelTest extends AbstractDockingTest {

	private PathnameTablePanel panel;
	private JTable table;
	private JFrame frame;
	private String[] tablePaths =
		{ "c:\\path_one", "c:\\path_two", "c:\\path_three", "c:\\path_four", "c:\\path_five" };

	@Before
	public void setUp() throws Exception {
		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		panel = new PathnameTablePanel(tablePaths, true, false, () -> reset());
		table = panel.getTable();
		frame = new JFrame("Test");
		frame.getContentPane().add(panel);
		runSwing(() -> frame.setVisible(true));
	}

	@After
	public void tearDown() throws Exception {
		frame.setVisible(false);
	}

	@Test
	public void testUpArrow() throws Exception {
		selectRow(3);
		JButton upButton = findButtonByIcon(panel, ResourceManager.loadImage("images/up.png"));
		assertNotNull(upButton);
		pressButton(upButton, true);
		waitForPostedSwingRunnables();

		int row = table.getSelectedRow();
		assertEquals(2, row);
		assertEquals("c:\\path_four", table.getModel().getValueAt(row, 0));

		pressButton(upButton, true);
		waitForPostedSwingRunnables();
		row = table.getSelectedRow();
		assertEquals(1, row);
		assertEquals("c:\\path_four", table.getModel().getValueAt(row, 0));

		pressButton(upButton, true);
		waitForPostedSwingRunnables();
		row = table.getSelectedRow();
		assertEquals(0, row);
		assertEquals("c:\\path_four", table.getModel().getValueAt(row, 0));

		pressButton(upButton, true);
		waitForPostedSwingRunnables();
		row = table.getSelectedRow();
		assertEquals(4, row);
		assertEquals("c:\\path_four", table.getModel().getValueAt(row, 0));
	}

	@Test
	public void testDownArrow() throws Exception {
		selectRow(2);

		JButton downButton = findButtonByIcon(panel, ResourceManager.loadImage("images/down.png"));
		assertNotNull(downButton);
		pressButton(downButton, true);
		waitForPostedSwingRunnables();

		int row = table.getSelectedRow();
		assertEquals(3, row);
		assertEquals("c:\\path_three", table.getModel().getValueAt(row, 0));

		pressButton(downButton, true);
		waitForPostedSwingRunnables();
		row = table.getSelectedRow();
		assertEquals(4, row);
		assertEquals("c:\\path_three", table.getModel().getValueAt(row, 0));

		pressButton(downButton, true);
		waitForPostedSwingRunnables();
		row = table.getSelectedRow();
		assertEquals(0, row);
		assertEquals("c:\\path_three", table.getModel().getValueAt(row, 0));

		pressButton(downButton, true);
		waitForPostedSwingRunnables();
		row = table.getSelectedRow();
		assertEquals(1, row);
		assertEquals("c:\\path_three", table.getModel().getValueAt(row, 0));
	}

	@Test
	public void testRemove() throws Exception {
		selectRow(4);

		JButton button =
			findButtonByIcon(panel, ResourceManager.loadImage("images/edit-delete.png"));
		assertNotNull(button);
		pressButton(button, true);
		waitForPostedSwingRunnables();
		int row = table.getSelectedRow();
		assertEquals(3, row);

		pressButton(button, true);
		waitForPostedSwingRunnables();
		row = table.getSelectedRow();
		assertEquals(2, row);

		pressButton(button, true);
		waitForPostedSwingRunnables();
		row = table.getSelectedRow();
		assertEquals(1, row);

		pressButton(button, true);
		waitForPostedSwingRunnables();
		row = table.getSelectedRow();
		assertEquals(0, row);

		pressButton(button, true);
		waitForPostedSwingRunnables();
		row = table.getSelectedRow();
		assertEquals(-1, row);

		assertTrue(!button.isEnabled());
	}

	@Test
	public void testAddButton() throws Exception {
		File temp = createTempFileForTest();

		Preferences.setProperty(Preferences.LAST_IMPORT_DIRECTORY, temp.getParent());
		panel.setFileChooserProperties("Select Source Files", Preferences.LAST_IMPORT_DIRECTORY,
			GhidraFileChooserMode.FILES_AND_DIRECTORIES, true,
			new ExtensionFileFilter(new String[] { "h" }, "C Header Files"));

		JButton button = findButtonByIcon(panel, ResourceManager.loadImage("images/Plus.png"));
		assertNotNull(button);
		pressButton(button, false);

		waitForPostedSwingRunnables();
		selectFromFileChooser();

		assertEquals(6, table.getRowCount());

		String filename = (String) table.getModel().getValueAt(5, 0);
		assertTrue(filename.endsWith("fred.h"));
	}

	@Test
	public void testCancelAdd() throws Exception {

		File temp = createTempFileForTest();

		Preferences.setProperty(Preferences.LAST_IMPORT_DIRECTORY, temp.getParent());
		panel.setFileChooserProperties("Select Source Files", Preferences.LAST_IMPORT_DIRECTORY,
			GhidraFileChooserMode.FILES_AND_DIRECTORIES, true,
			new ExtensionFileFilter(new String[] { "h" }, "C Header Files"));

		JButton button = findButtonByIcon(panel, ResourceManager.loadImage("images/Plus.png"));
		assertNotNull(button);
		pressButton(button, false);

		waitForPostedSwingRunnables();
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
		SwingUtilities.invokeAndWait(() -> panel.clear());
		assertEquals(0, table.getRowCount());
	}

	@Test
	public void testAddToTop() throws Exception {

		panel.setAddToTop(true);
		File temp = createTempFileForTest();
		Preferences.setProperty(Preferences.LAST_IMPORT_DIRECTORY, temp.getParent());
		panel.setFileChooserProperties("Select Source Files", Preferences.LAST_IMPORT_DIRECTORY,
			GhidraFileChooserMode.FILES_AND_DIRECTORIES, true,
			new ExtensionFileFilter(new String[] { "h" }, "C Header Files"));

		JButton button = findButtonByIcon(panel, ResourceManager.loadImage("images/Plus.png"));
		assertNotNull(button);
		pressButton(button, false);

		waitForPostedSwingRunnables();
		selectFromFileChooser();

		assertEquals(6, table.getRowCount());

		String filename = (String) table.getModel().getValueAt(0, 0);
		assertTrue(filename.endsWith("fred.h"));

	}

	@Test
	public void testReset() throws Exception {
		JButton removeButton =
			findButtonByIcon(panel, ResourceManager.loadImage("images/edit-delete.png"));
		JButton addButton = findButtonByIcon(panel, ResourceManager.loadImage("images/Plus.png"));
		JButton resetButton =
			findButtonByIcon(panel, ResourceManager.loadImage("images/trash-empty.png"));

		assertNotNull(removeButton);
		assertNotNull(addButton);
		assertNotNull(resetButton);

		selectRow(4);

		pressButton(removeButton, true);
		waitForPostedSwingRunnables();
		int row = table.getSelectedRow();
		assertEquals(3, row);

		pressButton(removeButton, true);
		waitForPostedSwingRunnables();
		row = table.getSelectedRow();
		assertEquals(2, row);

		pressButton(resetButton, false);
		waitForPostedSwingRunnables();

		pressResetConfirmation();

		int rowCount = table.getRowCount();
		assertEquals(5, rowCount);

		pressButton(addButton, false);
		waitForPostedSwingRunnables();

		selectFromFileChooser();

		rowCount = table.getRowCount();
		assertEquals(6, rowCount);

		pressButton(resetButton, false);
		waitForPostedSwingRunnables();

		pressResetConfirmation();

		rowCount = table.getRowCount();
		assertEquals(5, rowCount);
	}

	private void selectRow(final int row) throws Exception {
		runSwing(() -> table.setRowSelectionInterval(row, row));
	}

	private void pressResetConfirmation() {
		OptionDialog popup = waitForDialogComponent(OptionDialog.class);
		assertNotNull(popup);

		JButton yesButton = findButtonByText(popup, "Yes");
		assertNotNull(yesButton);

		pressButton(yesButton, true);
		waitForPostedSwingRunnables();
	}

	private void selectFromFileChooser() throws Exception {
		final GhidraFileChooser fileChooser = waitForDialogComponent(GhidraFileChooser.class);
		assertNotNull(fileChooser);

		JButton chooseButton = findButtonByText(fileChooser, "OK");
		assertNotNull(chooseButton);

		//JTextField filenameTextField = (JTextField)findComponentByName(fileChooser.getComponent(), "filenameTextField");
		//setJTextField(filenameTextField, "fred.h");
		runSwing(() -> fileChooser.setSelectedFile(
			new File(fileChooser.getCurrentDirectory(), "fred.h")));

		waitForUpdateOnChooser(fileChooser);

		pressButton(chooseButton, true);
		waitForPostedSwingRunnables();
	}

	private void reset() {
		LibrarySearchPathManager.reset();
		panel.setPaths(tablePaths);
	}

}
