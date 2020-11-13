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
/*
 * Created on Jul 12, 2006
 */
package docking.widgets.filechooser;

import static docking.widgets.filechooser.GhidraFileChooserMode.*;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.text.IsEmptyString.isEmptyOrNullString;
import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.FocusListener;
import java.awt.event.MouseEvent;
import java.io.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.table.JTableHeader;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.*;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.*;

import docking.*;
import docking.action.DockingAction;
import docking.test.AbstractDockingTest;
import docking.widgets.DropDownSelectionTextField;
import docking.widgets.SpyDropDownWindowVisibilityListener;
import docking.widgets.table.*;
import generic.concurrent.ConcurrentQ;
import ghidra.framework.*;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.worker.Worker;
import util.CollectionUtils;
import utilities.util.FileUtilities;

public class GhidraFileChooserTest extends AbstractDockingTest {

	private static final String ROOT_DIR_WINDOWS = "C:/";
	private static final String ROOT_DIR_MAC = "/";

	private static final String FAKE_FILE_WINDOWS = "C:/foobie/doobie/doo";
	private static final String FAKE_FILE_MAC = "/foobie/doobie/doo";

	private String operatingSystemDependentRootDirectory = ROOT_DIR_WINDOWS;
	private String operatingSystemDependentFakeFile = FAKE_FILE_WINDOWS;

	private static final int DEFAULT_TIMEOUT_MILLIS = 10000;

	private GhidraFileChooser chooser;
	private SpyDropDownWindowVisibilityListener<File> spy =
		new SpyDropDownWindowVisibilityListener<>();

	private File homeDir;
	private File tempdir;
	private File lastSelectedFile;

	@Before
	public void setUp() throws Exception {

		homeDir = new File(System.getProperty("user.home"));
		tempdir = new File(getTestDirectoryPath());

		//
		// Unusual Code Alert!: Cleanup old files that are left behind after test failures.  These
		//                      can clog the system and cause failures in odd ways.
		//
		cleanupOldTestFiles();

		OperatingSystem OS = Platform.CURRENT_PLATFORM.getOperatingSystem();
		if (OS == OperatingSystem.MAC_OS_X || OS == OperatingSystem.LINUX) {
			operatingSystemDependentRootDirectory = ROOT_DIR_MAC;
			operatingSystemDependentFakeFile = FAKE_FILE_MAC;
		}

		show();
	}

	@After
	public void tearDown() throws Exception {
		close();
	}

	@Test
	public void testBack() throws Exception {

		// go to the dirs to update the back stack
		List<File> files = createTempFilesInDifferentDirectories();
		for (File file : files) {
			setFile(file);
			waitForNewDirLoad(file.getParentFile());
		}

		File testDir = new File(getTestDirectoryPath());
		setFile(testDir);

		for (int i = files.size() - 1; i >= 0; --i) {
			pressBack();
			File parentFile = files.get(i).getParentFile();
			waitForChooser();
			assertEquals(
				"directory [" + i + "] has not been loaded after pressing back: " + parentFile,
				parentFile, getCurrentDirectory());
		}
	}

	@Test
	public void testShowWithARootDirectory() throws Exception {
		setMode(FILES_AND_DIRECTORIES);

		setFile(new File(operatingSystemDependentRootDirectory));

		pressOk();
		File file = getSelectedFile();
		assertEquals(new File(operatingSystemDependentRootDirectory), file);
	}

	// SCR 3392 - back button enablement; assert exception being triggered
	@Test
	public void testBackForSCR_3392() throws Exception {
		File currentDirectory = getCurrentDirectory();

		pressMyComputer();

		File newCurrentDirectory = getCurrentDirectory();
		assertFalse(currentDirectory.equals(newCurrentDirectory));

		JButton backButton = (JButton) getInstanceField("backButton", chooser);
		assertTrue(backButton.isEnabled());

		pressBack();
		waitForChooser();

		newCurrentDirectory = getCurrentDirectory();
		assertTrue(currentDirectory.equals(newCurrentDirectory));
	}

	// SCR 3358
	@Test
	public void testBackForSCR_3358() throws Exception {
		// start at a known dir
		File startDir = new File(getTestDirectoryPath());
		setFile(startDir);

		// move to the home area via the home button
		pressButtonByName(chooser.getComponent(), "HOME_BUTTON", false);
		waitForChooser();
		assertEquals(getCurrentDirectory(), homeDir);

		// create a new file
		pressNewFolderButton();
		waitForChooser();
		waitForSwing();

		DirectoryList dirlist = getListView();
		final File newFile = getNewlyCreatedFile(dirlist);
		waitForFile(newFile, DEFAULT_TIMEOUT_MILLIS);
		stopListEdit(dirlist);

		setDir(newFile);// go into the dir
		waitForChooser();

		// back should now go to the 'home' dir
		pressBack();
		waitForChooser();
		assertEquals("Did not go back to the home directory", homeDir, getCurrentDirectory());

		// finally,  go back to the start dir
		pressBack();
		waitForChooser();
		assertEquals("Did not go back to the start directory", startDir.getParentFile(),
			getCurrentDirectory());
	}

	@Test
	public void testUp() throws Exception {
		File testDir = new File(getTestDirectoryPath());
		setDir(testDir);

		pressButtonByName(chooser.getComponent(), GhidraFileChooser.UP_BUTTON_NAME);

		// We set the selected file to be a dir, so the start directory is that dir's parent.  We
		// hit the up button, which will move the dir up past that parent.
		File expectedFile = testDir.getParentFile();
		assertEquals(expectedFile, getCurrentDirectory());
		pressButtonByName(chooser.getComponent(), GhidraFileChooser.UP_BUTTON_NAME);
		assertEquals(expectedFile.getParentFile(), getCurrentDirectory());

		// now keep pressing up--it should fail eventually
		int upCount = 0;
		int magicStopValue = 10;
		while (upCount < magicStopValue) {
			upCount++;
			try {
				pressButtonByName(chooser.getComponent(), GhidraFileChooser.UP_BUTTON_NAME);
			}
			catch (AssertionError e) {
				// good!
				upCount = 0;
				break;
			}
		}

		if (upCount == magicStopValue) {
			fail("Shouldn't be able to press Up button after going up to the root!");
		}
	}

	@Test
	public void testNewFolderThenNavigateWithoutCancellingForSCR_4513() throws Exception {

		//  1) Click on the new folder button.
		//  2) Click on the "My Computer" button.
		//  3) Double-click on the root drive.
		//  3) Boom.

		// hack: the focus listeners can trigger an editCancelled(), which is a problem in 
		//       parallel mode
		DirectoryList dirlist = getListView();
		removeFocusListeners(dirlist);

		pressNewFolderButton();
		waitForSwing();
		waitForChooser();

		getNewlyCreatedFile(dirlist);// this forces us to wait for the new file to appear
		JTextField editorField =
			(JTextField) findComponentByName(chooser.getComponent(), "LIST_EDITOR_FIELD");
		assertNotNull(editorField);

		pressMyComputer();

		// Next, double-click the root drive entry
		DirectoryListModel model = (DirectoryListModel) dirlist.getModel();
		int rootIndex = model.indexOfFile(new File(operatingSystemDependentRootDirectory));
		assertTrue(rootIndex >= 0);

		Rectangle cellBounds = dirlist.getCellBounds(rootIndex, rootIndex);
		clickMouse(dirlist, MouseEvent.BUTTON1, cellBounds.x + 1, cellBounds.y + 1, 1, 0);
		waitForSwing();

		// any errors in the Swing thread will fail the test
	}

	@Test
	public void testNewFolderInList() throws Exception {
		setMode(DIRECTORIES_ONLY);

		DirectoryList dirlist = getListView();

		// hack: the focus listeners can trigger an editCancelled(), which is a problem in 
		//       parallel mode
		removeFocusListeners(dirlist);

		pressNewFolderButton();
		waitForSwing();
		waitForChooser();

		int selectedIndex;
		File newFile = getNewlyCreatedFile(dirlist);
		DirectoryListModel dirmodel = (DirectoryListModel) dirlist.getModel();

		JTextField editorField =
			(JTextField) findComponentByName(chooser.getComponent(), "LIST_EDITOR_FIELD");
		assertNotNull(editorField);
		String name = "Foo_" + Math.random();
		setText(editorField, name);
		stopListEdit(dirlist);

		selectedIndex = dirlist.getSelectedIndex();
		newFile = dirmodel.getFile(selectedIndex);
		assertEquals(name, newFile.getName());
		newFile.deleteOnExit();

		pressOk();
		File file = getSelectedFile();
		assertNotNull(file);
		assertEquals(name, file.getName());

		newFile.delete();
	}

	@Test
	public void testNewFolderInTable() throws Exception {
		setMode(DIRECTORIES_ONLY);
		pressDetailsButton();
		waitForChooser();

		pressNewFolderButton();
		waitForSwing();
		waitForChooser();

		DirectoryTable dirtable =
			(DirectoryTable) findComponentByName(chooser.getComponent(), "TABLE");
		DirectoryTableModel dirmodel = (DirectoryTableModel) dirtable.getModel();
		int selectedRow = dirtable.getSelectedRow();

		if (selectedRow < 0) {
			debugChooser();
			fail("Problem creating a new file in the file chooser's table");
		}
		assertTrue(selectedRow >= 0);
		File newFile = dirmodel.getFile(selectedRow);
		assertTrue(newFile.getName().startsWith(GhidraFileChooser.NEW_FOLDER));
		newFile.deleteOnExit();
		JTextField editorField =
			(JTextField) findComponentByName(chooser.getComponent(), "TABLE_EDITOR_FIELD");
		assertNotNull(editorField);
		String name = "Foo_" + Math.random();
		setText(editorField, name);

		// cannot use triggerEnter() here because that uses the actionPerformed() of the 
		// text field and our editor uses a key listener
		triggerEnter(editorField);
		waitForSwing();

		selectedRow = dirtable.getSelectedRow();
		newFile = dirmodel.getFile(selectedRow);
		assertEquals(name, newFile.getName());
		newFile.deleteOnExit();

		pressOk();
		assertEquals(name, getSelectedFile().getName());

		newFile.delete();
	}

	@Test
	public void testPickingFileFromDropDownListByTypingPartialTextAndThenPressingEnterForSCR_4406()
			throws Exception {

		String prefix = getName();
		File file = createTempFile(prefix);
		setDir(file);
		waitForChooser();

		//
		// look for a prefix that will match only one file
		//

		// a string long enough to make the pick unique, in case there are similarly named files
		String filenameText = prefix.substring(0, 13);
		typeTextForTextField(filenameText);
		triggerEnter(getFilenameTextField());

// the following code should be put back if we move to the Enter key press simply closing the
// matching dialog, as opposed to taking the selection and closing the chooser
//        // make sure the typed text has triggered the matching file to be selected
//        DirectoryList dirlist = (DirectoryList)findComponentByName(chooser.getComponent(), "LIST");
//        File newFile = getSelectedFile( dirlist, DEFAULT_TIMEOUT_MILLIS );
//        assertEquals( notepadFile, newFile );

		File selectedFile = getSelectedFile();
		assertEquals(file, selectedFile);
	}

	@Test
	public void testPickingNonExistentFileForSCR_3949() throws Exception {
		// We want to allow users to type in the name of a file that does not exist.  It is up
		// to the file chooser client to make sure the selected file exists.
		File nonExistentFile = new File(operatingSystemDependentFakeFile);
		setFilenameFieldText(nonExistentFile.getAbsolutePath());

		pressOk();
		assertTrue("File chooser did not close when selecting a non-existent file by typing text.",
			!chooser.isShowing());
		File selectedFile = getSelectedFile();
		assertEquals(nonExistentFile, selectedFile);
	}

	@Test
	public void testRefresh() throws Exception {
		setDir(tempdir);

		int size = chooser.getHistorySize();

		File tempfile = File.createTempFile(getName(), ".tmp", tempdir);
		tempfile.deleteOnExit();
		DirectoryList dirlist = getListView();
		assertNotNull(dirlist);
		DirectoryListModel dirmodel = (DirectoryListModel) dirlist.getModel();
		assertFalse(dirmodel.contains(tempfile));

		pressRefresh();
		waitForChooser();

		assertTrue(dirmodel.contains(tempfile));
		assertTrue(tempfile.delete());
		pressRefresh();
		waitForChooser();

		assertFalse(dirmodel.contains(tempfile));

		// verify back stack is not corrupted!!!
		assertEquals(size, size = chooser.getHistorySize());
	}

	// refresh was navigating into the selected directory
	@Test
	public void testRefreshForSCR_3380() throws Exception {

		// create a new file
		pressNewFolderButton();
		waitForSwing();

		DirectoryList dirlist = getListView();
		File newFile = getNewlyCreatedFile(dirlist);
		waitForFile(newFile, DEFAULT_TIMEOUT_MILLIS);

		// select the file in the chooser
		runSwing(() -> {
			Object directoryModel = getInstanceField("directoryModel", chooser);
			invokeInstanceMethod("setSelectedFile", directoryModel, new Class[] { File.class },
				new Object[] { newFile });
		});

		// press refresh
		pressRefresh();
		waitForFile(newFile, DEFAULT_TIMEOUT_MILLIS);

		// verify we did not go into the selected directory
		assertFalse(newFile.equals(getCurrentDirectory()));
	}

	/*
	 * The user should be able to enter a directory into the text field and navigate to that
	 * directory by pressing Enter or OK.
	 * <p>
	 * An absolute dir should navigate always.  A relative dir navigates if that directory is
	 * a child of the current directory.
	 */
	@Test
	public void testNavigateToDirectoryInFilesOnlyModeForSCR_5757() throws Exception {
		// Note: the default mode is FILES_ONLY mode
		File startingDir = getCurrentDirectory();

		//
		// Start with an absolute path
		//
		String tempDirPath = getTestDirectoryPath();
		assertNotNull("No system temp dir is defined!", tempDirPath);

		// first try the Enter key
		setFilenameFieldText(tempDirPath);
		triggerEnter(getFilenameTextField());
		waitForChooser();

		File absoluteTempDir = new File(tempDirPath);
		File currentDirectory = getCurrentDirectory();
		assertEquals("Entering an absolute dir path and pressing Enter did not " +
			"trigger a directory change!", absoluteTempDir, currentDirectory);
		assertTrue("File chooser closed after navigating", chooser.isShowing());

		// next try the OK button
		setDir(startingDir);

		currentDirectory = getCurrentDirectory();
		assertEquals("Did not return to the starting directory", startingDir, currentDirectory);

		setFilenameFieldText(tempDirPath);
		pressOk();
		waitForChooser();
		currentDirectory = getCurrentDirectory();
		assertEquals("Entering an absolute dir path and pressing OK did not " +
			"trigger a directory change!", absoluteTempDir, currentDirectory);
		assertTrue("File chooser closed after navigating", chooser.isShowing());

		//
		// Now try a relative dir
		//
		String tempDirName = "TestDirDeleteMe";
		File tempSubDir = createTempDirAndUpdateChooser(tempDirName);

		// first try the Enter key
		setFilenameFieldText(tempSubDir.getName());
		triggerEnter(getFilenameTextField());
		waitForChooser();
		currentDirectory = getCurrentDirectory();
		assertEquals("Entering a relative dir path and pressing Enter did not " +
			"trigger a directory change!", tempSubDir, currentDirectory);
		assertTrue("File chooser closed after navigating", chooser.isShowing());

		// next try the OK button
		setDir(absoluteTempDir);

		currentDirectory = getCurrentDirectory();
		assertEquals("Did not return to the temp starting directory", absoluteTempDir,
			currentDirectory);

		setFilenameFieldText(tempSubDir.getName());
		pressOk();
		waitForChooser();
		currentDirectory = getCurrentDirectory();
		assertEquals("Entering an absolute dir path and pressing OK did not " +
			"trigger a directory change!", tempSubDir, currentDirectory);
		assertTrue("File chooser closed after navigating", chooser.isShowing());

		FileUtilities.deleteDir(tempSubDir);
	}

	/*
	 * The user should be able to enter a directory into the text field and navigate to that
	 * directory by pressing Enter or OK.
	 * <p>
	 * An absolute dir should navigate always.  A relative dir is taken as a user selection, since
	 * we can't tell what the user wants when in this mode.
	 */
	@Test
	public void testNavigateToDirectoryInDirectoriesOnlyModeForSCR_5757() throws Exception {
		setMode(DIRECTORIES_ONLY);
		File startingDir = getCurrentDirectory();

		//
		// Start with an absolute path
		//
		String tempDirPath = getTestDirectoryPath();
		assertNotNull("No system temp dir is defined!", tempDirPath);

		// first try the Enter key
		setFilenameFieldText(tempDirPath);
		triggerEnter(getFilenameTextField());
		waitForChooser();

		File absoluteTempDir = new File(tempDirPath);
		File currentDir = getCurrentDirectory();
		assertEquals("Entering an absolute dir path and pressing Enter did not " +
			"trigger a directory change!", absoluteTempDir, currentDir);
		assertTrue("File chooser closed after navigating", chooser.isShowing());

		// next try the OK button
		setDir(startingDir);

		currentDir = getCurrentDirectory();
		assertEquals("Did not return to the starting directory", startingDir, currentDir);

		setFilenameFieldText(tempDirPath);
		pressOk();
		waitForChooser();
		currentDir = getCurrentDirectory();
		assertEquals("Entering an absolute dir path and pressing OK did not " +
			"trigger a directory change!", absoluteTempDir, currentDir);
		assertTrue("File chooser closed after navigating", chooser.isShowing());

		//
		// Now try a relative dir
		//
		String tempDirName = "TestDirDeleteMe";
		File tempSubDir = createTempDirAndUpdateChooser(tempDirName);

		// first try the Enter key
		setFilenameFieldText(tempSubDir.getName());
		triggerEnter(getFilenameTextField());
		waitForChooser();
		File selectedDir = getSelectedFile();
		assertEquals(
			"Entering a relative dir path and pressing Enter did not chooser that directory!",
			tempSubDir, selectedDir);
		assertFalse("File chooser did not close when selecting a valid, relative subdirectory!",
			chooser.isShowing());

		// re-launch the closed chooser
		setDir(absoluteTempDir);
		runSwing(() -> chooser.show(), false);
		waitForSwing();
		waitForNewDirLoad(absoluteTempDir);

		// next try the OK button
		setDir(absoluteTempDir);

		currentDir = getCurrentDirectory();
		assertEquals("Did not return to the temp starting directory", absoluteTempDir, currentDir);

		setFilenameFieldText(tempSubDir.getName());
		pressOk();
		waitForChooser();
		selectedDir = getSelectedFile();
		assertEquals(
			"Entering a relative dir path and pressing Enter did not chooser that directory!",
			tempSubDir, selectedDir);
		assertFalse("File chooser did not close when selecting a valid, relative subdirectory!",
			chooser.isShowing());
	}

	/*
	 * The user should be able to enter a directory into the text field and navigate to that
	 * directory by pressing Enter or OK.
	 * <p>
	 * An absolute dir should navigate always.  A relative dir is taken as a user selection, since
	 * we can't tell what the user wants when in this mode.
	 */
	@Test
	public void testNavigateToDirectoryInDirectoriesAndFilesModeForSCR_5757() throws Exception {
		setMode(FILES_AND_DIRECTORIES);
		File startingDir = getCurrentDirectory();

		//
		// Start with an absolute path
		//
		String tempDirPath = getTestDirectoryPath();
		assertNotNull("No system temp dir is defined!", tempDirPath);

		// first try the Enter key
		setFilenameFieldText(tempDirPath);
		triggerEnter(getFilenameTextField());
		waitForChooser();

		final File absoluteTempDir = new File(tempDirPath);
		File currentDir = getCurrentDirectory();
		assertEquals("Entering an absolute dir path and pressing Enter did not " +
			"trigger a directory change!", absoluteTempDir, currentDir);
		assertTrue("File chooser closed after navigating", chooser.isShowing());

		// next try the OK button
		setDir(startingDir);

		currentDir = getCurrentDirectory();
		assertEquals("Did not return to the starting directory", startingDir, currentDir);

		setFilenameFieldText(tempDirPath);
		pressOk();
		waitForChooser();
		currentDir = getCurrentDirectory();
		assertEquals("Entering an absolute dir path and pressing OK did not " +
			"trigger a directory change!", absoluteTempDir, currentDir);
		assertTrue("File chooser closed after navigating", chooser.isShowing());

		//
		// Now try a relative dir
		//
		String tempDirName = "TestDirDeleteMe";
		File tempSubDir = createTempDirAndUpdateChooser(tempDirName);

		// first try the Enter key
		setFilenameFieldText(tempSubDir.getName());
		triggerEnter(getFilenameTextField());
		waitForChooser();
		File selectedDir = getSelectedFile();
		assertEquals(
			"Entering a relative dir path and pressing Enter did not " + "chooser that directory!",
			tempSubDir, selectedDir);
		assertTrue("File chooser did not close when selecting a valid, relative subdirectory!",
			!chooser.isShowing());

		// re-launch the closed chooser
		setDir(absoluteTempDir);
		runSwing(() -> chooser.show(), false);
		waitForSwing();
		waitForNewDirLoad(absoluteTempDir);

		// next try the OK button
		setDir(absoluteTempDir);

		currentDir = getCurrentDirectory();
		assertEquals("Did not return to the temp starting directory", absoluteTempDir, currentDir);

		setFilenameFieldText(tempSubDir.getName());
		pressOk();
		waitForChooser();
		selectedDir = getSelectedFile();
		assertEquals(
			"Entering a relative dir path and pressing Enter did not " + "chooser that directory!",
			tempSubDir, selectedDir);
		assertTrue("File chooser did not close when selecting a valid, relative subdirectory!",
			!chooser.isShowing());
	}

	// this is to test a condition where the file chooser would not let you pick a directory
	// within a directory when they shared the same name
	@Test
	public void testDirectoryInDirectory() throws Exception {
		setMode(FILES_AND_DIRECTORIES);
		DirectoryList dirlist = getListView();

		// hack: the focus listeners can trigger an editCancelled(), which is a problem in 
		//       parallel mode
		removeFocusListeners(dirlist);

		// create a new file...
		pressNewFolderButton();
		waitForSwing();

		final File newFile = getNewlyCreatedFile(dirlist);
		stopListEdit(dirlist);

		setDir(newFile);

		// go into the newly created directory
		assertTrue(getCurrentDirectory().equals(newFile));
		waitForChooser();

		// create another new file with the same name
		pressNewFolderButton();
		waitForSwing();
		waitForChooser();

		// get the new file and make sure that it is in the rename/edit mode
		final File newFile2 = getNewlyCreatedFile(dirlist);
		newFile2.deleteOnExit();
		waitForFile(newFile2, DEFAULT_TIMEOUT_MILLIS);
		waitForSwing();
		JTextField editorField =
			(JTextField) findComponentByName(chooser.getComponent(), "LIST_EDITOR_FIELD");
		assertNotNull(editorField);

		// set the name of the new file to match the parent directory
		String name = newFile.getName();
		setText(editorField, name);
		stopListEdit(dirlist);

		// ...then select that directory and press O.K.
		waitForSwing();
		waitForChooser();
		File file = getSelectedFile(dirlist, DEFAULT_TIMEOUT_MILLIS);

		pressOk();

		// make sure we get the newly created file and that the file chooser did not simply
		// ignore our selection and stay open
		assertEquals(file, getSelectedFile());

		// child then parent
		newFile2.delete();
		newFile.delete();
	}

	private void removeFocusListeners(DirectoryList dirlist) {
		FocusListener[] listeners = dirlist.getListEditorText().getFocusListeners();
		for (FocusListener l : listeners) {
			dirlist.getListEditorText().removeFocusListener(l);
		}
	}

	// this error happens when adding a relative directory name that is the leaf name of the
	// current directory
	@Test
	public void testChooseDirectoryByTextWhenInsideThatDirectory() throws Exception {
		setMode(DIRECTORIES_ONLY);
		final File file = new File(getTestDirectoryPath());
		setDir(file);

		waitForChooser();

		// there once was a bug that would double append the dir name when setting the text...
		String dirName = file.getName();
		setFilenameFieldText(dirName);

		pressOk();

		File selectedFile = getSelectedFile();
		assertEquals(file.getAbsolutePath(), selectedFile.getAbsolutePath());
	}

	/*
	 * Test that an update/refresh of the current directory does not interfere with the user's
	 * editing of the text field, which may include the drop-down selection window.
	 */
	@Test
	public void testUpdateOnDirectoryDoesNotCloseUserDropDownSelectionWindow() throws Exception {

		// start typing some text that will trigger the matching window.  The starting dir for
		// the chooser in the test environment is user.home.  We will put in a temp file so that
		// we can guarantee that what we type will end up triggering the matching window.

		// the code that closes (before the fix) the matching window is the code that restores
		// the selected item, which updates the chooser's text field.  So, we have to make sure
		// we have a selection in the GUI before we trigger the matching window.
		File userHomeDir = getCurrentDirectory();
		File tempFile = createTempFileInCurrentDirectoryAndUpdateChooser(getName() + "_tempFile");
		setFile(tempFile);

		File selectedFile = getSelectedFile();
		assertEquals("The test file was not selected", tempFile, selectedFile);

		assertDropDownWindowIsShowing(false);// make sure the window is not up yet

		setFilenameFieldText("");// clear any text so that we can trigger the matching window
		String desktopText = "test";
		typeTextForTextField(desktopText);

		assertDropDownWindowIsShowing(true);

		// now force an update of the directory (we must manually call one of the chooser's
		// private methods in order to simulate a reload condition where the current selection is
		// restored).
		invokeInstanceMethod("updateDirAndSelectFile", chooser,
			new Class[] { File.class, File.class, boolean.class, boolean.class },
			new Object[] { userHomeDir, tempFile, Boolean.TRUE, Boolean.FALSE });

		waitForChooser();

		selectedFile = getSelectedFile();
		assertEquals("The test file was not selected again after a refresh", tempFile,
			selectedFile);

		assertDropDownWindowIsShowing(true);
		String currentText = getFilenameFieldText();
		assertEquals("Somehow the text of the text field was changed and the drop-down " +
			"window was left open", desktopText, currentText);
	}

	// test that choosing a directory in 'files only' mode will navigate to that directory and
	// not chooser that directory
	@Test
	public void testDirectoryInFileOnlyMode() throws Exception {
		setMode(FILES_ONLY);
		File file = new File(getTestDirectoryPath());
		setDir(file.getParentFile());

		assertEquals(file.getParentFile(), getCurrentDirectory());

		// relative
		String dirName = file.getName();
		setFilenameFieldText(dirName);

		pressOk();
		assertTrue("File chooser was closed when choosing a directory in 'files only' mode",
			chooser.isShowing());

		File selectedFile = getCurrentDirectory();
		assertEquals(file.getAbsolutePath(), selectedFile.getAbsolutePath());

		// reset the directory
		setDir(file.getParentFile());

		assertEquals(file.getParentFile(), getCurrentDirectory());

		setFilenameFieldText(file.getAbsolutePath());

		pressOk();
		assertTrue("File chooser was closed when choosing a directory in 'files only' mode",
			chooser.isShowing());

		selectedFile = getCurrentDirectory();
		assertEquals(file.getAbsolutePath(), selectedFile.getAbsolutePath());
	}

	@Test
	public void testDirectoryInFileOnlyMode_Selection_NoTextFieldText() throws Exception {

		/* 
		 * test when a user single clicks a directory name and clicks the action button 
		 * when the filename text field is empty
		 */

		setMode(FILES_ONLY);
		File dir = new File(getTestDirectoryPath());
		setDir(dir.getParentFile());
		assertEquals(dir.getParentFile(), getCurrentDirectory());

		setFilenameFieldText(null);

		setFile(dir);

		pressOk();
		waitForChooser();

		assertTrue("File chooser was closed when choosing a directory and clicking OK " +
			"button in 'files only' mode, blank filename field.  Selected file: " +
			lastSelectedFile, chooser.isShowing());

		assertEquals(dir, getCurrentDirectory());

	}

	@Test
	public void testDirectoryInFileOnlyMode_Selection_WithTextFieldText() throws Exception {

		/* 
		 * test when a user single clicks a directory name and clicks the action button 
		 * when the filename text field has a value
		 */

		setMode(FILES_ONLY);
		File dir = new File(getTestDirectoryPath());
		setDir(dir.getParentFile());
		assertEquals(dir.getParentFile(), getCurrentDirectory());

		setFilenameFieldText("some_filename_doesnt_matter");

		setFile(dir);

		pressOk();
		waitForChooser();

		assertTrue("File chooser was closed when choosing a directory and clicking OK " +
			"button in 'files only' mode, with something in filename field.  Selected file: " +
			lastSelectedFile, chooser.isShowing());

		assertEquals(dir, getCurrentDirectory());

	}

	@Test
	public void testSelectCurrentDirectoryInDiretoriesOnlyModeForSCR_3932() throws Exception {
		// In normal mode the user must select a file or directory (or type one in) in order to
		// have a valid selection.  However, in 'directories only' mode we all the user to press
		// OK with no file selected in order to use the current directory.  This may seem
		// inconsistent, but when choosing a directory it is convenient.

		// clear any selection
		setFile(null);

		// Force chooser into user's home directory as it always exists
		File testDir = getHomeDir();
		setDir(testDir);

		setMode(FILES_AND_DIRECTORIES);

		// press OK and make sure we get an error message
		pressOk();
		assertTrue("The file chooser accepted the current directory when not in 'directories " +
			"only' mode.", chooser.isShowing());

		setMode(FILES_ONLY);

		// press OK and make sure we get an error message
		pressOk();
		assertTrue("The file chooser accepted the current directory when not in 'directories " +
			"only' mode.", chooser.isShowing());

		setMode(DIRECTORIES_ONLY);

		// press OK and make sure we DO NOT get an error message
		pressOk();
		assertTrue("The did not accept the current directory in 'directories only' mode.",
			!chooser.isShowing());
	}

	@Test
	public void testShowDetails() throws Exception {
		JPanel cardPanel = (JPanel) findComponentByName(chooser.getComponent(), "CARD_PANEL");
		DirectoryList dirlist = getListView();
		JTable dirtable = getTableView();
		JScrollPane scrollpane1 = (JScrollPane) cardPanel.getComponent(0);
		JScrollPane scrollpane2 = (JScrollPane) cardPanel.getComponent(1);
		assertEquals(dirtable, scrollpane1.getViewport().getComponent(0));
		assertEquals(dirlist, scrollpane2.getViewport().getComponent(0));
		assertFalse(scrollpane1.isVisible());
		assertTrue(scrollpane2.isVisible());

		pressDetailsButton();
		waitForChooser();

		assertTrue(scrollpane1.isVisible());
		assertFalse(scrollpane2.isVisible());

		pressDetailsButton();
		waitForChooser();

		assertFalse(scrollpane1.isVisible());
		assertTrue(scrollpane2.isVisible());
		close();
	}

	@Test
	public void testSortingByFileName() throws Exception {
		pressDetailsButton();
		waitForSwing();
		JTable dirtable = getTableView();
		DirectoryTableModel model = (DirectoryTableModel) dirtable.getModel();
		JTableHeader header = dirtable.getTableHeader();
		Rectangle rect = header.getHeaderRect(DirectoryTableModel.FILE_COL);

		clickMouse(header, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForChooser();
		doCompareTest(model);

		clickMouse(header, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForChooser();
		doCompareTest(model);
	}

	@Test
	public void testSortingByFileSzie() throws Exception {
		pressDetailsButton();
		JTable dirtable = getTableView();
		DirectoryTableModel model = (DirectoryTableModel) dirtable.getModel();
		JTableHeader header = dirtable.getTableHeader();
		Rectangle rect = header.getHeaderRect(DirectoryTableModel.SIZE_COL);

		clickMouse(header, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForChooser();
		doCompareTest(model);

		clickMouse(header, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForChooser();
		doCompareTest(model);
	}

	@Test
	public void testSortingByFileDate() throws Exception {
		pressDetailsButton();
		JTable dirtable = getTableView();
		DirectoryTableModel model = (DirectoryTableModel) dirtable.getModel();
		JTableHeader header = dirtable.getTableHeader();
		Rectangle rect = header.getHeaderRect(DirectoryTableModel.TIME_COL);

		clickMouse(header, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForChooser();
		doCompareTest(model);

		clickMouse(header, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForChooser();
		doCompareTest(model);
	}

	@Test
	public void testSelectingDirectoryForSCR_3638() throws Exception {
		// create some 'recent' files
		List<File> files = createTempFilesInDifferentDirectories();
		for (File file : files) {
			setFile(file);
			pressOk();
			assertTrue("Failed to select recent file: " + file, !chooser.isShowing());
			show();
		}

		setMode(DIRECTORIES_ONLY);
		pressRecent();

		// make a selection
		File fileToSelect = files.get(0).getParentFile();
		setFile(fileToSelect);

		// press the OK button and make sure that the new directory is our test file
		pressOk();
		File selectedFile = getSelectedFile();
		assertEquals("Unable to choose recent file that is a directory", fileToSelect,
			selectedFile);
	}

	@Test
	public void testSelectInvalidFileInSpecialDirectory() throws Exception {
		// make sure the user cannot type in relative filenames when in a special dir (like
		// Recent and My Computer)

		pressRecent();

		setFilenameFieldText("foo");

		// press OK and verify we have an error message
		pressOk();
		assertTrue("The file chooser accepted an invalid file parented by the RECENTs directory",
			chooser.isShowing());

		pressMyComputer();

		setFilenameFieldText("foo");

		// press OK and verify we have an error message
		pressOk();
		assertTrue(
			"The file chooser accepted an invalid file parented by the My Computer directory",
			chooser.isShowing());
	}

	/*
	 *  NOTE: make sure this test matches the features described by
	 *  {@link GhidraFileChooser#setSelectedFile(File)}
	 */
	@Test
	public void testSetSelectedFile() throws Exception {
		// set a file to be selected and make sure it gets selected and set a directory selected
		// and make sure it's parent is made active and it becomes selected within the parent

		final File testDataDirectory = new File(getTestDirectoryPath());
		File regularFile = createTempFile();

		setFile(regularFile);

		DirectoryList dirlist = getListView();
		File file = getSelectedFile(dirlist, DEFAULT_TIMEOUT_MILLIS);
		assertNotNull(file);
		assertEquals(regularFile.getName().toUpperCase(), file.getName().toUpperCase());

		setFile(testDataDirectory);

		file = getSelectedFile(dirlist, DEFAULT_TIMEOUT_MILLIS);
		assertNotNull(file);
		assertEquals(testDataDirectory.getName().toUpperCase(), file.getName().toUpperCase());

		File newFile = getSelectedFile(dirlist, DEFAULT_TIMEOUT_MILLIS);
		assertEquals(testDataDirectory, newFile);

		//
		// Make sure we can set a file with a valid parent directory, but no existing file.  This
		// should set the current directory to the parent directory and then put the filename in
		// the text field.
		//
		String tempDirPath = getTestDirectoryPath();
		assertNotNull("No system temp dir is defined!", tempDirPath);
		File tempDir = new File(tempDirPath);
		File nonExistentFile =
			createNonExistentTempFile(tempDir, "non.existent.test.filename.delete.me");
		setFile(nonExistentFile);

		String filenameFieldText = getFilenameFieldText();
		assertEquals("The filename field's text was not set when calling setSelectedFile() with " +
			"a non-existent file", nonExistentFile.getName(), filenameFieldText);
	}

	@Test
	public void testSetSelectedFileForSCR_3923() throws Exception {
		// This checks for the bug where setting the selected file to a directory would navigate
		// into that directory instead of selecting that directory in the view.  In order to make
		// a give directory be the current directory you must call setCurrentDirectory()
		// instead of setSelectedFile()

		// Set the selected file to be a directory and then show the file chooser.
		// Verify that the directory is selected and that it is not the current directory

		// This bug is seen when you:
		// -show the chooser and set the selected file to 'foo'
		// -close the chooser
		// -set the selected file to 'foo' again
		// -show the chooser
		// -at this point the current dir is foo and not foo's parent
		File directory = new File(getTestDirectoryPath());
		setFile(directory);

		DirectoryList dirlist = getListView();
		File selectedFile = getSelectedFile(dirlist, DEFAULT_TIMEOUT_MILLIS);
		assertNotNull(selectedFile);
		assertEquals(directory.getName().toUpperCase(), selectedFile.getName().toUpperCase());

		// close the chooser and try again
		pressOk();

		setFile(directory);

		executeOnSwingWithoutBlocking(() -> chooser.getSelectedFile());
		waitForChooser();

		File currentDirectory = getCurrentDirectory();
		assertNotNull(currentDirectory);
		assertEquals(directory.getParentFile().getName().toUpperCase(),
			currentDirectory.getName().toUpperCase());
	}

	@Test
	public void testSetSelectedFileNonExistent_NameTextIsSelected() throws Exception {

		File testDataDirectory = new File(getTestDirectoryPath());
		String nonExistentFilename = getClass().getName() + ".foo.bar.baz.test";
		File badFileWithGoodParent = new File(testDataDirectory, nonExistentFilename);
		showWithFile(badFileWithGoodParent);

		JTextField textField = getFilenameTextField();
		assertEquals(badFileWithGoodParent.getName(), textField.getText());
		assertFalse(runSwing(() -> StringUtils.isBlank(textField.getSelectedText())));
	}

	@Test
	public void testSetSelectedFileNonExistent_InFilesOnlyMode() throws Exception {
		setMode(FILES_ONLY);
		doTestSetSelectedFileNonExistent();
	}

	@Test
	public void testSetSelectedFileNonExistent_InFilesAndDirectoriesOnlyMode() throws Exception {
		setMode(FILES_AND_DIRECTORIES);
		doTestSetSelectedFileNonExistent();
	}

	@Test
	public void testSetSelectedFileNonExistent_InDirectoriesOnlyMode() throws Exception {
		setMode(DIRECTORIES_ONLY);

		// verify:
		//
		// -in GhidraFileChooser.DIRECTORIES_ONLY mode we do not put non-existent filenames
		//  in the text field, but we do put existing file names in the field
		//
		String nonExistentFilename = getClass().getName() + ".foo.bar.baz.test";
		File testDataDirectory = new File(getTestDirectoryPath());
		final File regularFile = new File(testDataDirectory, nonExistentFilename);

		// sanity check
		File startSelectedFile = chooser.getSelectedFile();
		assertTrue("The initial dir of the file chooser is the same as the test's start " +
			"file--need to change the start file!", !regularFile.equals(startSelectedFile));

		setFile(regularFile);

		JTextField textField = getFilenameTextField();
		assertEquals(regularFile.getName(), textField.getText());
	}

	public void doTestSetSelectedFileNonExistent() throws Exception {
		// verify:
		//
		// -a non-existent file with an existing parent dir selects the dir and puts in the file text
		//
		File testDataDirectory = new File(getTestDirectoryPath());
		String nonExistentFilename = getClass().getName() + ".foo.bar.baz.test";
		final File regularFile = new File(testDataDirectory, nonExistentFilename);

		// sanity check
		File startSelectedFile = getSelectedFile();
		assertTrue("The initial dir of the file chooser is the same as the test's start " +
			"file--need to change the start file!", !regularFile.equals(startSelectedFile));

		setFile(regularFile);

		JTextField textField = getFilenameTextField();
		assertEquals(regularFile.getName(), textField.getText());

		File directory = (File) invokeInstanceMethod("currentDirectory", chooser);
		assertNotNull(directory);
		assertEquals(regularFile.getParentFile(), directory);

		//
		// -that a non-existent file with a non-existent parent clears the selected file
		//
		File crazyFile = new File("C:/alpha/bravo/charlie", nonExistentFilename);

		setFile(crazyFile, false);

		File selectedFile = getSelectedFile();
		assertNull("The chooser still has a selected file after calling " +
			"setSelectedFile(File) with an invalid file", selectedFile);
	}

	@Test
	public void testTypingInDirectoryNameUsesTheTextAndNotTheSelectedFile_FilenameOnly()
			throws Exception {
		//
		// This is to test a bug where the user navigates to a directory and selects a child
		// directory, and then finally types a different directory name in the chooser text field.
		// We expect the chooser to use the typed text over the selected file.
		//

		File startDir = new File(getTestDirectoryPath());
		setDir(startDir);

		List<File> files = getExistingFiles(startDir, 2);

		setFile(files.get(0));

		// now put the a different file name in the text field and make sure that file is returned
		File wantedFile = files.get(1);
		setFilenameFieldText(wantedFile.getName());
		triggerEnter(getFilenameTextField());

		File selectedFile = getSelectedFile();
		assertEquals(wantedFile, selectedFile);
	}

	@Test
	public void testTypingRelativePathInTextField() throws Exception {
		//
		// This tests that the user can type a path relative to the current directory and the
		// chooser will return the correct file.
		//

		File startDir = createTempDir();
		setDir(startDir);

		File wantedFile = createFileSubFile(startDir, 3);

		// now put the relative path in the text field and make sure that file is returned
		String relativePath = FileUtilities.relativizePath(startDir, wantedFile);
		List<String> parts = FileUtilities.pathToParts(relativePath);
		assertTrue(parts.size() > 1); // sanity check

		setFilenameFieldText(relativePath);
		pressOk();

		File selectedFile = getSelectedFile();
		assertEquals(wantedFile, selectedFile);
	}

	@Test
	public void testTypingInDirectoryNameUsesTheTextAndNotTheSelectedFile_AbsolutePath()
			throws Exception {
		//
		// This is to test a bug where the user navigates to a directory and selects a child
		// directory, and then finally types a different absolute path in the chooser text field.
		// We expect the chooser to use the typed text over the selected file.
		//

		File startDir = createTempDir();
		setDir(startDir);

		File wantedFile = createFileSubFile(startDir, 3);
		setFilenameFieldText(wantedFile.getAbsolutePath());
		pressOk();

		File selectedFile = getSelectedFile();
		assertEquals(wantedFile, selectedFile);
	}

	@Test
	public void testRenameInList() throws Exception {
		doRenameTest(chooser.getActionManager(), "LIST_EDITOR_FIELD");
	}

	@Test
	public void testRenameInTable() throws Exception {
		setTableMode();
		waitForSwing();
		doRenameTest(chooser.getActionManager(), "TABLE_EDITOR_FIELD");
	}

	@Test
	public void testMyComputer() throws Exception {
		pressMyComputer();

		DirectoryList dirlist = getListView();
		DirectoryListModel listModel = (DirectoryListModel) dirlist.getModel();
		File[] roots = chooser.getModel().getRoots();
		assertEquals(roots.length, listModel.getSize());
		for (File element : roots) {
			listModel.contains(element);
		}

		// verify that the user cannot select anything when only the My Computer node is selected
		// with no selection in the display
		pressOk();

		assertTrue("Closed file chooser when no user selection was possible.", chooser.isShowing());
		assertFalse("Did not receive expected error message",
			StringUtils.isEmpty(chooser.getStatusText()));
	}

	/*
	 * Tests GhidraFileChooser's Desktop button to ensure it changes to the user's native 
	 * desktop directory.  This test is skipped if there is no native desktop directory.
	 */
	@Test
	public void testDesktop_SystemNativeDesktop() throws Exception {
		File userDesktopDir = chooser.getModel().getDesktopDirectory();

		if (userDesktopDir == null) {
			Msg.warn(this, "NOTE: unable to test 'Desktop' button in GhidraFileChooser " +
				"in this enviornment because it does not have a detectable Desktop folder.");
			return;
		}

		pressDesktop();
		waitForChooser();

		assertEquals("File chooser did not switch to the user's Desktop directory", userDesktopDir,
			getCurrentDirectory());
	}

	/*
	 * Tests GhidraFileChooser's Desktop button to ensure it is disabled when there is no 
	 * user Desktop directory
	 */
	@Test
	public void testMissingDesktop() throws Exception {

		// close existing chooser window so we can make a new special one 
		runSwing(() -> chooser.close());
		waitForSwing();

		// use a stubbed chooser model that has no Desktop
		GhidraFileChooserModel gfcm = new LocalFileChooserModel() {
			@Override
			public File getDesktopDirectory() {
				return null;
			}
		};
		show(gfcm, true);

		File userDesktopDir = chooser.getModel().getDesktopDirectory();
		assertNull("getDesktopDirectory() returned from GhidraFileChooserModel should be null",
			userDesktopDir);

		try {
			pressDesktop();
			fail("Desktop btton should have been disabled");
		}
		catch (AssertionError e) {
			// good
		}
	}

	/*
	 * Tests GhidraFileChooser's Desktop button to ensure it is works by creating a 
	 * fake user desktop directory.
	 */
	@Test
	public void testDesktop_InjectedDesktop() throws Exception {
		// close existing chooser window so we can make a new special one
		runSwing(() -> chooser.close());
		waitForSwing();

		// use a stubbed chooser model that has a non-native Desktop value
		final File fakeUserDesktopDir = createTempDirectory("faked_desktop_dir");

		GhidraFileChooserModel gfcm = new LocalFileChooserModel() {
			@Override
			public File getDesktopDirectory() {
				return fakeUserDesktopDir;
			}
		};
		show(gfcm, true);

		File userDesktopDir = chooser.getModel().getDesktopDirectory();
		assertEquals("getDesktopDirectory() is not our faked stub", fakeUserDesktopDir,
			userDesktopDir);

		pressDesktop();
		waitForChooser();

		assertEquals(
			"Clicking on 'Desktop' button in chooser did not switch the stub fake desktop dir",
			fakeUserDesktopDir, getCurrentDirectory());
	}

	@Test
	public void testHome() throws Exception {
		pressHome();
		waitForChooser();
		assertEquals("File chooser did not switch to the user's home directory", getHomeDir(),
			getCurrentDirectory());

		// check the chooser contents
		DirectoryList dirlist = getListView();
		DirectoryListModel listModel = (DirectoryListModel) dirlist.getModel();
		File[] listing = chooser.getModel().getListing(homeDir, null);
		assertEquals(listing.length, listModel.getSize());
		for (File element : listing) {
			listModel.contains(element);
		}
	}

	@Test
	public void testRecent() throws Exception {
		List<File> files = createTempFilesInDifferentDirectories();
		for (File file : files) {
			setFile(file);
			pressOk();
			show();
		}

		pressRecent();

		DirectoryList dirlist = getListView();
		DirectoryListModel listModel = (DirectoryListModel) dirlist.getModel();
		for (File element : files) {
			assertTrue("model does not contain the recent file: " + element.getParentFile(),
				listModel.contains(element.getParentFile()));
		}
	}

	@Test
	public void testRecentRemove() throws Exception {

		FileChooserActionManager actionManager = chooser.getActionManager();
		DockingAction removeAction = actionManager.getRemoveRecentAction();
		assertNotNull(removeAction);

		ActionContext context = createDirListContext();
		boolean isEnabled = isEnabled(removeAction, context);
		assertFalse(
			"'Remove Recent' action should not be enabled when not in the 'Recent' directory",
			isEnabled);

		List<File> files = createTempFilesInDifferentDirectories();
		for (File file : files) {
			setFile(file);
			pressOk();
			show();
		}

		pressRecent();

		// must re-retrieve the action, since we created a new chooser
		actionManager = chooser.getActionManager();
		removeAction = actionManager.getRemoveRecentAction();
		context = createDirListContext();
		isEnabled = isEnabled(removeAction, context);
		assertFalse("'Remove Recent' action should not be enabled when no file is selected",
			isEnabled);

		File file = files.get(files.size() - 1).getParentFile();
		selectFiles(Arrays.asList(file));
		waitForChooser();

		context = createDirListContext();
		isEnabled = isEnabled(removeAction, context);
		assertTrue("'Remove Recent' action should be enabled when a 'recent' file is selected",
			isEnabled);

		performAction(removeAction, context, true);
		waitForChooser();
		assertFalse(containsRecentFile(file));
	}

	@Test
	public void testFileFilter() throws Exception {
		DirectoryList dirlist = getListView();
		DirectoryListModel listModel = (DirectoryListModel) dirlist.getModel();
		runSwing(() -> chooser.setFileFilter(new ExtensionFileFilter("exe", "Executables")));

		File file = new File(getTestDirectoryPath());
		setDir(file);

		waitForNewDirLoad(file);

		for (int i = 0; i < listModel.getSize(); ++i) {
			File file1 = listModel.getFile(i);
			assertTrue(file1.getName() + " did not match file filter",
				chooser.getModel().isDirectory(file1) ||
					file1.getName().toLowerCase().endsWith("exe"));
		}

		runSwing(() -> chooser.setFileFilter(new ExtensionFileFilter("exe", "dll")));
		setDir(file);

		waitForNewDirLoad(file);

		for (int i = 0; i < listModel.getSize(); ++i) {
			File file1 = listModel.getFile(i);
			assertTrue(file1.getName() + " did not match file filter",
				chooser.getModel().isDirectory(file1) ||
					file1.getName().toLowerCase().endsWith("exe") ||
					file1.getName().toLowerCase().endsWith("dll"));
		}
	}

	@Test
	public void testRememberSettings_Size() throws Exception {
		//
		// A place to remember settings like size and the type of view showing
		//

		// Enable tracing to catch odd test failure
		LoggingInitialization.initializeLoggingSystem();
		Logger logger = LogManager.getLogger(GhidraFileChooser.class);
		Configurator.setLevel(logger.getName(), Level.TRACE);

		final JComponent component = chooser.getComponent();
		Dimension originalSize = component.getSize();
		DockingDialog dialog = (DockingDialog) getInstanceField("dialog", chooser);

		final Dimension updatedSize =
			new Dimension(originalSize.width * 2, originalSize.height * 2);
		runSwing(() -> dialog.setSize(updatedSize));

		// close to save the changes
		close();

		// load the saved changes
		show(false);

		final AtomicReference<Dimension> preferredSizeReference = new AtomicReference<>();
		runSwing(() -> {
			Dimension preferredSize = chooser.getDefaultSize();
			preferredSizeReference.set(preferredSize);
		});

		assertEquals("File chooser did not remember last picked size", updatedSize,
			preferredSizeReference.get());
	}

	@Test
	public void testRememberSettings_DetailsView() throws Exception {
		//
		// A place to remember settings like size and the type of view showing
		//

		// Enable tracing to catch odd test failure
		LoggingInitialization.initializeLoggingSystem();
		Logger logger = LogManager.getLogger(GhidraFileChooser.class);
		Configurator.setLevel(logger.getName(), Level.TRACE);

		JComponent component = chooser.getComponent();
		EmptyBorderToggleButton detailsButton =
			(EmptyBorderToggleButton) findComponentByName(component, "DETAILS_BUTTON");
		final boolean wasSelected = detailsButton.isSelected();
		runSwing(() -> chooser.setShowDetails(!wasSelected));
		waitForChooser();

		assertEquals(!wasSelected, detailsButton.isSelected());

		// close to save the changes
		close();

		// load the saved changes
		show(false);

		JComponent newComponent = chooser.getComponent();
		EmptyBorderToggleButton newDetailsButtons =
			(EmptyBorderToggleButton) findComponentByName(newComponent, "DETAILS_BUTTON");
		boolean isSelected = newDetailsButtons.isSelected();

		assertEquals(!wasSelected, isSelected);
	}

	@Test
	public void testFilenameAutoLookup_InTable() throws Exception {

		// Note: the table auto lookup is tested elsewhere.  This test is just making sure that 
		//       the feature responds within the file chooser.

		// dir file names start with 'a_...', 'b_...', etc
		TestFiles files = createAlphabeticMixedDirectory();

		showMultiSelectionChooser(files.parent, FILES_ONLY);

		setTableMode();
		DirectoryTable table = getTableView();
		int testTimeoutMs = 100;
		table.setAutoLookupTimeout(testTimeoutMs);

		selectFile(table, 0);
		focus(table);

		triggerText(table, "b");
		assertSelectedIndex(table, 1);

		sleep(testTimeoutMs);
		triggerText(table, "c");
		assertSelectedIndex(table, 2);

		sleep(testTimeoutMs);
		triggerText(table, "d");
		assertSelectedIndex(table, 3);

		sleep(testTimeoutMs);
		triggerText(table, "b");
		assertSelectedIndex(table, 1);
	}

	@Test
	public void testFilenameAutoLookup_InList() throws Exception {

		// dir file names start with 'a_...', 'b_...', etc
		TestFiles files = createAlphabeticMixedDirectory();

		showMultiSelectionChooser(files.parent, FILES_ONLY);

		setListMode();
		DirectoryList list = getListView();
		int testTimeoutMs = 100;
		list.setAutoLookupTimeout(testTimeoutMs);

		selectFile(list, 0);
		focus(list);

		triggerText(list, "b");
		assertSelectedIndex(list, 1);

		sleep(testTimeoutMs);
		triggerText(list, "c");
		assertSelectedIndex(list, 2);

		sleep(testTimeoutMs);
		triggerText(list, "d");
		assertSelectedIndex(list, 3);

		sleep(testTimeoutMs);
		triggerText(list, "b");
		assertSelectedIndex(list, 1);
	}

	@Test
	public void testFilenameAutoLookup_InList_SimilarNames() throws Exception {

		// dir file names start with 'dir1', 'dir1', 'file1...', 'file2...', etc
		TestFiles files = createMixedDirectory();

		showMultiSelectionChooser(files.parent, FILES_ONLY);

		DirectoryList list = getListView();
		int testTimeoutMs = 100;
		list.setAutoLookupTimeout(testTimeoutMs);

		setListMode();
		selectFile(list, 0);
		focus(list);

		triggerText(list, "d");
		assertSelectedIndex(list, 1);

		sleep(testTimeoutMs);
		triggerText(list, "d");
		assertSelectedIndex(list, 2);

		sleep(testTimeoutMs);
		triggerText(list, "f");
		assertSelectedIndex(list, 3);

		sleep(testTimeoutMs);
		triggerText(list, "f");
		assertSelectedIndex(list, 4);

		sleep(testTimeoutMs);
		triggerText(list, "d");
		assertSelectedIndex(list, 0);
	}

	@Test
	public void testFocus_FilesViewStaysFocusedAfterRefresh() throws Exception {

		if (BATCH_MODE) {
			// I don't like this, but these seem to have a focus sensitivity that
			// does not work correctly in headless
			return;
		}

		DirectoryList list = getListView();
		focus(list);

		clickMyComputer();
		assertTrue(list.hasFocus());

		clickRecent();
		assertTrue(list.hasFocus());

		clickBack();
		assertTrue(list.hasFocus());
	}

	@Test
	public void testHistoryRestoresSelectedFiles() throws Exception {

		File startDir = createTempDir();
		File subDir = createFileSubFile(startDir, 3);
		setDir(subDir);

//		// debug
//		DirectoryList list = getListView();
//		ListSelectionModel sm = list.getSelectionModel();
//		sm.addListSelectionListener(e -> {
//			Msg.debug(this, "selection changed: " + e);
//		});

		pressUp();
		selectFile(getListView(), 1);
		assertSelectedIndex(getListView(), 1);

		pressUp();
		selectFile(getListView(), 2);
		assertSelectedIndex(getListView(), 2);

		pressBack();
		assertSelectedIndex(getListView(), 1);

		pressForward();
		assertSelectedIndex(getListView(), 2);
	}

	@Test
	public void testGetSelectedFiles_FileOnlyMode_FileSelected() throws Exception {

		TestFiles files = createMixedDirectory();

		CompletableFuture<List<File>> results = showMultiSelectionChooser(files.parent, FILES_ONLY);

		File f = files.randomFile();
		setFile(f);

		pressOk();
		assertChooserHidden();
		assertChosen(results, f);
	}

	@Test
	public void testGetSelectedFiles_DirOnlyMode_DirSelected() throws Exception {

		TestFiles files = createMixedDirectory();

		CompletableFuture<List<File>> results =
			showMultiSelectionChooser(files.parent, DIRECTORIES_ONLY);

		File f = files.randomDir();
		setFile(f);

		pressOk();
		assertChooserHidden();
		assertChosen(results, f);
	}

	@Test
	public void testGetSelectedFiles_Cancel() throws Exception {

		TestFiles files = createMixedDirectory();

		CompletableFuture<List<File>> results = showMultiSelectionChooser(files.parent, FILES_ONLY);

		File f = files.randomFile();
		setFile(f);

		pressCancel();
		assertChooserHidden();

		assertNothingChosen(results);
	}

	@Test
	public void testGetSelectedFiles_OkWithNoSelection() throws Exception {

		// set selected file with non-existent file with non-existent parent dir

		TestFiles files = createMixedDirectory();

		showMultiSelectionChooser(files.parent, FILES_ONLY);

		setFile(null);

		pressOk();
		assertChooserVisible();
	}

	@Test
	public void testGetSelectedFiles_FilesOnlyMode_OnlyDirsSelected() throws Exception {
		TestFiles files = createMixedDirectory();

		CompletableFuture<List<File>> results = showMultiSelectionChooser(files.parent, FILES_ONLY);

		selectFiles(files.dirs);

		pressOk();
		assertChooserVisible();
		assertStatusText("Please select a file");
		assertNothingChosen(results);
	}

	@Test
	public void testGetSelectedFiles_FilesOnlyMode_MixedSelection() throws Exception {
		TestFiles files = createMixedDirectory();

		CompletableFuture<List<File>> results = showMultiSelectionChooser(files.parent, FILES_ONLY);

		selectFiles(CollectionUtils.asIterable(files.files, files.dirs));

		pressOk();
		assertChooserHidden();
		assertChosen(results, files.files); // dirs are dropped
	}

	@Test
	public void testGetSelectedFiles_MixedMode_MixedSelection() throws Exception {
		TestFiles files = createMixedDirectory();

		CompletableFuture<List<File>> results =
			showMultiSelectionChooser(files.parent, GhidraFileChooserMode.FILES_AND_DIRECTORIES);

		selectFiles(CollectionUtils.asIterable(files.files, files.dirs));

		pressOk();
		assertChooserHidden();
		assertChosen(results, CollectionUtils.asIterable(files.files, files.dirs)); // dirs are dropped
	}

	@Test
	public void testSelectingFileUpdatesTheTextField_SingleSelection() throws Exception {

		TestFiles files = createMixedDirectory();
		showSingleSelectionChooser(files.parent, GhidraFileChooserMode.FILES_ONLY);

		File file = files.files.get(0);
		selectFiles(file);

		waitForChooser();
		String filenameFieldText = getFilenameFieldText();
		assertEquals("Filename text field not updated upon file selection", file.getName(),
			filenameFieldText);
	}

	@Test
	public void testSelectingFileUpdatesTheTextField_MultiSelection() throws Exception {

		TestFiles files = createMixedDirectory();
		showMultiSelectionChooser(files.parent, GhidraFileChooserMode.FILES_ONLY);

		File file = files.files.get(0);
		selectFiles(file);

		//		
		// A single file selection will set the text field text
		// 
		waitForChooser();
		String filenameFieldText = getFilenameFieldText();
		assertEquals("Filename text field not updated upon file selection", file.getName(),
			filenameFieldText);

		//
		// A multi-selection will clear the text field text
		// 
		selectFiles(files.files);
		waitForChooser();
		filenameFieldText = getFilenameFieldText();
		assertThat("Filename text field not cleared upon multi-file selection", filenameFieldText,
			isEmptyOrNullString());

		//
		// Clear the multi-selection; a single file selection will set the text field text
		// 
		selectFiles(file);
		waitForChooser();
		filenameFieldText = getFilenameFieldText();
		assertEquals("Filename text field not updated upon file selection", file.getName(),
			filenameFieldText);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private List<File> getExistingFiles(File dir, int count) {
		assertTrue(dir.isDirectory());

		File[] files = dir.listFiles(f -> f.isFile());
		assertTrue("Dir does not contain enough files - '" + dir + "'; count = " + count,
			files.length >= count);

		// create some consistency between runs
		Arrays.sort(files, (f1, f2) -> f1.getName().compareTo(f2.getName()));

		List<File> result = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			result.add(files[i]);
		}
		return result;
	}

	private boolean containsRecentFile(File file) {

		@SuppressWarnings("unchecked")
		List<RecentGhidraFile> recents =
			(List<RecentGhidraFile>) getInstanceField("recentList", chooser);
		for (RecentGhidraFile recent : recents) {
			File actual = recent.getAbsoluteFile();
			if (file.equals(actual)) {
				return true;
			}
		}

		return false;
	}

	private ActionContext createDirListContext() {

		DirectoryList dirlist = getListView();
		return new ActionContext(null, dirlist);
	}

	private boolean isEnabled(DockingAction action, ActionContext context) {
		return runSwing(() -> action.isEnabledForContext(context));
	}

	private void assertSelectedIndex(DirectoryList list, int expected) {
		int actual = runSwing(() -> list.getSelectedIndex());

		// debug code
		if (expected != actual) {
			waitForCondition(() -> expected == actual,
				"Wrong list index selected ");
		}
	}

	private void assertSelectedIndex(GTable table, int expected) {
		int actual = runSwing(() -> table.getSelectedRow());
		assertEquals("Wrong table row selected", expected, actual);
	}

	private File selectFile(DirectoryList list, int index) {

		// TODO debug - remove when all tests passing on server
		int size = list.getModel().getSize();
		Msg.debug(this, "selectFile() - new index: " + index + "; list size: " + size);

		runSwing(() -> list.setSelectedIndex(index));
		return runSwing(() -> list.getSelectedFile());
	}

	private File selectFile(DirectoryTable table, int index) {
		runSwing(() -> table.getSelectionModel().setSelectionInterval(index, index));
		return runSwing(() -> table.getSelectedFile());
	}

	private void focus(Component c) {
		runSwing(() -> c.requestFocus());
		waitForSwing();
	}

	private void setFile(File file) throws Exception {
		setFile(file, true);
	}

	private void setFile(File file, boolean wait) throws Exception {
		runSwing(() -> chooser.setSelectedFile(file));
		waitForChooser();

		if (!wait) {
			return;
		}

		if (file == null) {
			waitForCondition(() -> chooser.getSelectedFile(false) == null);
		}
		else {
			waitForCondition(() -> chooser.getSelectedFile(false).equals(file));
		}
	}

	private void selectFiles(File file) {
		selectFiles(CollectionUtils.asIterable(file));
	}

	private void selectFiles(Iterable<File> files) {
		DirectoryList dirlist = getListView();
		runSwing(() -> dirlist.setSelectedFiles(files));
	}

	private void setMode(GhidraFileChooserMode mode) {
		runSwing(() -> chooser.setFileSelectionMode(mode));
	}

	private void pressOk() {
		pressButtonByText(chooser.getComponent(), "OK");
		waitForSwing();
	}

	private void pressCancel() {
		pressButtonByText(chooser.getComponent(), "Cancel");
		waitForSwing();
	}

	private void setTableMode() {
		AbstractButton button = (AbstractButton) findComponentByName(chooser.getComponent(),
			"DETAILS_BUTTON");
		boolean isSelected = runSwing(() -> button.isSelected());
		if (!isSelected) {
			// toggle from the table 'details mode'
			pressDetailsButton();
		}
	}

	private void setListMode() {
		AbstractButton button = (AbstractButton) findComponentByName(chooser.getComponent(),
			"DETAILS_BUTTON");
		boolean isSelected = runSwing(() -> button.isSelected());
		if (isSelected) {
			// toggle from the table 'details mode'
			pressDetailsButton();
		}
	}

	private void pressDetailsButton() {
		pressButtonByName(chooser.getComponent(), "DETAILS_BUTTON");
		waitForSwing();
	}

	private void pressMyComputer() throws Exception {
		pressButtonByName(chooser.getComponent(), "MY_COMPUTER_BUTTON", false);
		waitForChooser();
	}

	private void clickMyComputer() throws Exception {
		AbstractButton button =
			(AbstractButton) findComponentByName(chooser.getComponent(), "MY_COMPUTER_BUTTON");
		leftClick(button, 5, 5);
		waitForChooser();
	}

	private void clickRecent() throws Exception {
		AbstractButton button =
			(AbstractButton) findComponentByName(chooser.getComponent(), "RECENT_BUTTON");
		leftClick(button, 5, 5);
		waitForChooser();
	}

	private void clickBack() throws Exception {
		AbstractButton button =
			(AbstractButton) findComponentByName(chooser.getComponent(), "BACK_BUTTON");
		leftClick(button, 5, 5);
		waitForChooser();
	}

	private void pressRecent() throws Exception {
		pressButtonByName(chooser.getComponent(), "RECENT_BUTTON", false);
		waitForChooser();
	}

	private void pressHome() {
		pressButtonByName(chooser.getComponent(), "HOME_BUTTON", false);
		waitForSwing();
	}

	private void pressDesktop() {
		pressButtonByName(chooser.getComponent(), "DESKTOP_BUTTON", false);
		waitForSwing();
	}

	private void pressNewFolderButton() {
		pressButtonByName(chooser.getComponent(), "NEW_BUTTON");
		waitForSwing();
	}

	private void pressRefresh() {
		pressButtonByName(chooser.getComponent(), "REFRESH_BUTTON");
		waitForSwing();
	}

	private void pressBack() throws Exception {
		pressButtonByName(chooser.getComponent(), "BACK_BUTTON");
		waitForSwing();
		waitForChooser();
	}

	private void pressForward() throws Exception {
		pressButtonByName(chooser.getComponent(), "FORWARD_BUTTON");
		waitForSwing();
		waitForChooser();
	}

	private void pressUp() throws Exception {
		pressButtonByName(chooser.getComponent(), "UP_BUTTON");
		waitForSwing();
		waitForChooser();
	}

	private void setDir(final File dir) throws Exception {
		runSwing(() -> chooser.setCurrentDirectory(dir));
		waitForChooser();
	}

	private void stopListEdit(DirectoryList dirlist) {
		runSwing(() -> dirlist.stopListEdit());
		waitForSwing();
	}

	private File createTempFileInCurrentDirectoryAndUpdateChooser(String filename)
			throws Exception {

		File parentDir = getCurrentDirectory();
		myDeleteMatchingTempFiles(parentDir, "_tempFile");
		File tempFile = File.createTempFile(filename, null, parentDir);
		tempFile.deleteOnExit();

		chooser.rescanCurrentDirectory();
		waitForChooser();

		assertChooserListContains(tempFile);

		return tempFile;
	}

	private void myDeleteMatchingTempFiles(File dir, String string) {

		File[] files = dir.listFiles(f -> f.getName().contains(string));
		if (files != null) {
			for (File f : files) {
				f.delete();
			}
		}
	}

	private File createNonExistentTempFile(File parentDir, String filename) throws Exception {
		// We are going to use a trick here: create temp file to get a valid temp name and then
		// delete that file so that we can create a directory by that name
		File tempFile = File.createTempFile(filename, null, parentDir);
		tempFile.delete();
		assertTrue("Unable to delete temp file: " + tempFile, !tempFile.exists());
		return tempFile;
	}

	private File createTempDirAndUpdateChooser(String filename) throws Exception {
		// We are going to use a trick here: create temp file to get a valid temp name and then
		// delete that file so that we can create a directory by that name
		File parentDir = getCurrentDirectory();
		File tempFile = File.createTempFile(filename, null, parentDir);
		tempFile.delete();
		assertTrue("Unable to delete temp file: " + tempFile, !tempFile.exists());

		assertTrue("Unable to make temp directory: " + tempFile.getAbsolutePath(),
			tempFile.mkdir());

		chooser.rescanCurrentDirectory();
		waitForChooser();

		tempFile.deleteOnExit();

		return tempFile;
	}

	private void assertDropDownWindowIsShowing(boolean isShowing) {

		if (isShowing) {
			if (!spy.wasWindowShown()) {
				Msg.debug(this, "Drop-down window not showing:\n" + spy);
			}
			assertTrue(
				"The drop-down matching window of the file chooser is not showing as expected",
				spy.wasWindowShown());
		}
		else {

			if (spy.wasWindowShown()) {
				boolean wasHidden = spy.wasWindowHidden();
				if (!wasHidden) {
					Msg.debug(this, "Drop-down window not hidden:\n" + spy);
				}

				assertTrue("The drop-down matching window of the file chooser is " +
					"showing when it is not expected to be.", wasHidden);
			}
		}
		//spy.reset();
	}

	private void assertNothingChosen(CompletableFuture<List<File>> results) throws Exception {

		if (!results.isDone()) {
			return; // not finished; nothing chosen
		}

		// not sure we need any timeout--it should already be ready
		List<File> selected = results.get(2, TimeUnit.SECONDS);
		assertThat(selected, is(empty()));
	}

	private void assertChosen(CompletableFuture<List<File>> results, File... expected)
			throws Exception {
		assertChosen(results, Arrays.asList(expected));
	}

	private void assertChosen(CompletableFuture<List<File>> results, Iterable<File> expected)
			throws Exception {

		// not sure we need any timeout--it should already be ready
		List<File> selected = results.get(2, TimeUnit.SECONDS);
		List<File> list = CollectionUtils.asList(expected);
		assertEquals(list.size(), selected.size());
		assertListEqualUnordered(null, list, selected);
		// Unfortunate that Matchers does not have a containsInAnyOrder that takes a collection
		//assertThat(selected, containsInAnyOrder(expected.toArray()));
	}

	private void assertStatusText(String expected) {
		assertEquals(expected, runSwing(() -> chooser.getStatusText()));
	}

	private void removeFocusIssuesInBatchMode() {

		// install our own custom visibility listener for debugging
		DropDownSelectionTextField<?> field = getFilenameTextField();
		setInstanceField("windowVisibilityListener", field, spy);

		if (!BATCH_MODE) {
			// Batch mode has focus issue when running in parallel.  In this case, update
			// the drop-down field to disable closing the popup window during focus changes.  By
			// only doing this in batch mode, the test can still be run by a developer with
			// the normal behavior.		
			return;
		}

		FocusListener[] focusListeners = field.getFocusListeners();
		for (FocusListener l : focusListeners) {
			field.removeFocusListener(l);
		}
	}

	private void typeTextForTextField(String text) {
		JTextField textField = getFilenameTextField();
		triggerText(textField, text);
		waitForSwing();
	}

	private void doCompareTest(DirectoryTableModel model) {
		FileComparator comparator =
			new FileComparator(chooser.getModel(), model.getPrimarySortColumnIndex());
		for (int i = 0; i < model.getRowCount() - 1; ++i) {
			File file1 = model.getFile(i + 0);
			File file2 = model.getFile(i + 1);
			int value = comparator.compare(file1, file2);

			TableSortState sortState = model.getTableSortState();
			ColumnSortState columnSortState =
				sortState.getColumnSortState(model.getPrimarySortColumnIndex());

			if (columnSortState.isAscending()) {
				assertTrue(value <= 0);
			}
			else {
				assertTrue(value >= 0);
			}
		}
	}

	private void setFilenameFieldText(final String text) {
		final JTextField textField = getFilenameTextField();
		runSwing(() -> textField.requestFocusInWindow());

		runSwing(() -> textField.setText(text));
	}

	private String getFilenameFieldText() {
		final JTextField textField = getFilenameTextField();
		return textField.getText();
	}

	private DropDownSelectionTextField<?> getFilenameTextField() {
		DropDownSelectionTextField<?> textField =
			(DropDownSelectionTextField<?>) getInstanceField("filenameTextField", chooser);
		return textField;
	}

	private void show() throws Exception {
		show(true);
	}

	private void show(boolean useDefaults) throws Exception {
		show(null, useDefaults);
	}

	private CompletableFuture<List<File>> showSingleSelectionChooser(File dir,
			GhidraFileChooserMode mode) throws Exception {

		close();

		CompletableFuture<List<File>> theFuture = new CompletableFuture<>();

		chooser = new GhidraFileChooser(null);
		chooser.setFileSelectionMode(mode);

		runSwing(() -> {
			chooser.setCurrentDirectory(dir);
			chooser.setMultiSelectionEnabled(false);
			List<File> choice = chooser.getSelectedFiles();
			theFuture.complete(choice);
		}, false);

		initialize(chooser, dir, true);

		return theFuture;
	}

	private CompletableFuture<List<File>> showMultiSelectionChooser(File dir,
			GhidraFileChooserMode mode) throws Exception {
		close();

		CompletableFuture<List<File>> theFuture = new CompletableFuture<>();

		chooser = new GhidraFileChooser(null);
		chooser.setFileSelectionMode(mode);

		runSwing(() -> {
			chooser.setCurrentDirectory(dir);
			chooser.setMultiSelectionEnabled(true);
			List<File> choice = chooser.getSelectedFiles();
			theFuture.complete(choice);
		}, false);

		initialize(chooser, dir, true);

		return theFuture;
	}

	private void showWithFile(File file) throws Exception {

		close();

		chooser = new GhidraFileChooser(null);

		File dir = file.getParentFile();
		runSwing(() -> {
			chooser.setCurrentDirectory(dir);
			chooser.setMultiSelectionEnabled(true);
			chooser.setSelectedFile(file);
			lastSelectedFile = chooser.getSelectedFile(true);
		}, false);

		initialize(chooser, dir, true);
	}

	private void show(GhidraFileChooserModel gfcm, boolean useDefaults) throws Exception {
		// show dot files by default, as that is how the tests were written
		Preferences.setProperty(GFileChooserOptionsDialog.SHOW_DOT_FILES_PROPERTY_NAME,
			Boolean.TRUE.toString());
		Preferences.store();

		chooser = (gfcm != null) ? new GhidraFileChooser(gfcm, null) : new GhidraFileChooser(null);

		runSwing(() -> {
			chooser.setCurrentDirectory(getHomeDir());
			chooser.show();
			lastSelectedFile = chooser.getSelectedFile(false);
		}, false);
		waitForSwing();

		initialize(chooser, getHomeDir(), useDefaults);
	}

	private void initialize(GhidraFileChooser newChooser, File dir, boolean useDefaults)
			throws Exception {
		if (useDefaults) {
			runSwing(() -> {
				chooser.setShowDetails(false);// default to list view
				Dimension defaultSize = new Dimension(600, 350);
				chooser.getComponent().setPreferredSize(defaultSize);// default size)
				invokeInstanceMethod("repack", chooser);
			});
		}

		waitForNewDirLoad(dir);
		waitForChooser();

		removeFocusIssuesInBatchMode();
	}

	private void close() throws Exception {
		if (chooser.isShowing()) {
			pressCancel();
		}
	}

	private File createTempFile() throws IOException {
		File file = createTempFile(getName() + "test.dir");
		return file;
	}

	// Note: this is meant to replace createTempDirectory(String name), as that method will
	//       delete previously created temp directories and files, which we do not want.  This
	//       test may need to create multiple temp directories.
	private File myCreateTempDirectory(String name) throws IOException {

		String testTempDir = getTestDirectoryPath();
		Path testTempDirPath = Paths.get(testTempDir);
		Path tempDirPath = Files.createTempDirectory(testTempDirPath, name);
		return tempDirPath.toFile();
	}

	private File createTempDir() throws IOException {
		File dir = myCreateTempDirectory(getName());
		return dir;
	}

	private List<File> createTempFilesInDifferentDirectories() throws IOException {
		List<File> list = new ArrayList<>();

		for (int i = 0; i < 4; i++) {
			File dir = myCreateTempDirectory(getName() + "test.dir." + i);
			File file = myCreateTempFile(dir, "test.file");
			list.add(file);
		}

		return list;
	}

	private File createFileSubFile(File dir, int levels) throws IOException {

		File lastFile = null;
		File parentDir = dir;
		for (int i = 0; i < levels; i++) {

			if (i < (levels - 1)) {
				// prepare the next parent
				parentDir = myCreateTempDirectory(dir, getName() + "test.dir." + i);
			}
			else {
				// last file
				lastFile = myCreateTempFile(parentDir, "test.file");
			}
		}

		return lastFile;
	}

	private File myCreateTempFile(File parent, String subName) throws IOException {
		File file = File.createTempFile(getName() + subName, null, parent);
		file.deleteOnExit();
		return file;
	}

	private File myCreateTempFileWithPrefix(File parent, String prefix) throws IOException {
		File file = File.createTempFile(prefix + '_' + getName(), null, parent);
		file.deleteOnExit();
		return file;
	}

	private File myCreateTempDirectory(File parent, String name) throws IOException {

		File userDir = new File(parent, name);
		FileUtils.deleteDirectory(userDir); // shouldn't exist already
		userDir.mkdirs();
		userDir.deleteOnExit();
		return userDir;
	}

	private void doRenameTest(FileChooserActionManager actionManager, String editorName)
			throws Exception {
		final File tempfile = File.createTempFile(getName(), ".tmp", tempdir);
		tempfile.deleteOnExit();
		waitForSwing();

		setFile(tempfile);

		waitForNewDirLoad(tempfile.getParentFile());

		DockingAction renameAction = actionManager.getRenameAction();
		assertNotNull(renameAction);

		performAction(renameAction, false);
		waitForSwing();

		JTextField editorField =
			(JTextField) findComponentByName(chooser.getComponent(), editorName);

		if (editorField == null) {
			debugChooser();
		}

		assertNotNull(editorField);
		String name = "Foo_" + Math.random() + ".tmp";
		setText(editorField, name);
		triggerEnter(editorField);

		editorField = (JTextField) findComponentByName(chooser.getComponent(), editorName);

		if (editorField != null) {
			String statusText = chooser.getStatusText();
			fail("Editor field was not hidden after pressing enter - status: " + statusText +
				" and current value: " + editorField.getText());
		}

		assertFalse(tempfile.exists());
		File newTempFile = new File(tempfile.getParentFile(), name);
		newTempFile.deleteOnExit();
		assertTrue("New file was not created after a rename: " + newTempFile, newTempFile.exists());

		if (editorName.equals("TABLE_EDITOR_FIELD")) {
			DirectoryTable table =
				(DirectoryTable) findComponentByName(chooser.getComponent(), "TABLE");
			File selectedFile = getSelectedFile(table, DEFAULT_TIMEOUT_MILLIS);
			assertEquals(name, selectedFile.getName());
		}
		else {
			DirectoryList dirlist = getListView();
			File selectedFile = getSelectedFile(dirlist, DEFAULT_TIMEOUT_MILLIS);
			assertEquals(name, selectedFile.getName());
		}
	}

	// waits for the given change ID to change...also attempts to wait out a barrage of changes
	private void waitForChooser() throws Exception {
		waitForSwing();

		int tryCount = 0;
		while (tryCount++ < 5) {
			waitForConditionWithoutFailing(() -> !chooser.pendingUpdate());
		}

		if (chooser.pendingUpdate()) {
			fail("Timed-out waiting for file chooser to update.\nChooser still running job: " +
				getChooserJob());
		}

		waitForSwing();
	}

	private void waitForNewDirLoad(File file) throws Exception {

		int waits = 0;
		while (waits++ < 5) {
			waitForConditionWithoutFailing(() -> getCurrentDirectory().equals(file));
		}

		assertTrue(
			"Timed-out waiting for chooser to load dir: " + file.getAbsolutePath() +
				".\n\tActual directory is " + chooser.getCurrentDirectory(),
			getCurrentDirectory().equals(file));

		waitForChooser();

		// make sure swing has handled any pending changes
		waitForSwing();
	}

	private String getChooserJob() {
		Worker worker = (Worker) getInstanceField("worker", chooser);
		ConcurrentQ<?, ?> cq = (ConcurrentQ<?, ?>) getInstanceField("concurrentQ", worker);
		Queue<?> q = (Queue<?>) getInstanceField("queue", cq);
		Object[] jobs = q.toArray();
		return Arrays.toString(jobs);
	}

	private void waitForFile(File file, int timeoutMillis) throws Exception {
		DirectoryListModel listModel =
			(DirectoryListModel) getInstanceField("directoryListModel", chooser);
		int totalTime = 0;
		while (!listModel.contains(file) && totalTime < timeoutMillis) {
			sleep(DEFAULT_WAIT_DELAY);
			totalTime += DEFAULT_WAIT_DELAY;
		}

		if (totalTime >= timeoutMillis) {
			fail("Timed-out waiting for filechooser to load: " + file.getAbsolutePath());
		}
	}

	private File getCurrentDirectory() {
		return runSwing(() -> chooser.getCurrentDirectory());
	}

	private File getSelectedFile() {
		return runSwing(() -> chooser.getSelectedFile(false));
	}

	private File getHomeDir() {
		return chooser.getModel().getHomeDirectory();
	}

	private File getNewlyCreatedFile(DirectoryList dirlist) throws Exception {

		// artificially high wait period that won't be reached most of the time
		int timeoutMillis = DEFAULT_TIMEOUT_MILLIS;
		File newFile = getSelectedFile(dirlist, timeoutMillis);

		assertNotNull("New file never created!", newFile);

		assertTrue(newFile.getName().startsWith(GhidraFileChooser.NEW_FOLDER));
		newFile.deleteOnExit();
		return newFile;
	}

	private File getSelectedFile(DirectoryList dirlist, int timeoutMillis) throws Exception {
		DirectoryListModel dirmodel = (DirectoryListModel) dirlist.getModel();
		int selectedIndex = dirlist.getSelectedIndex();

		int totalTime = 0;
		while ((selectedIndex < 0) && (totalTime < timeoutMillis)) {
			sleep(50);
			totalTime += 50;
			selectedIndex = dirlist.getSelectedIndex();
		}

		assertTrue("No file was selected!", selectedIndex >= 0);
		return dirmodel.getFile(selectedIndex);
	}

	private void assertChooserListContains(File expected) {

		DirectoryList dirlist = getListView();
		ListModel<?> model = dirlist.getModel();
		int size = model.getSize();
		for (int i = 0; i < size; i++) {

			File f = (File) model.getElementAt(i);
			if (f.equals(expected)) {
				return;
			}
		}

		debugChooser();
		fail("File chooser does not in its list have file: " + expected);
	}

	private void assertChooserHidden() {
		assertFalse("The chooser is showing; it should be closed",
			runSwing(() -> chooser.isShowing()));
	}

	private void assertChooserVisible() {
		assertTrue("The chooser is hidden; it should be showing",
			runSwing(() -> chooser.isShowing()));
	}

	private File getSelectedFile(DirectoryTable table, int timeoutMillis) throws Exception {
		DirectoryTableModel dirmodel = (DirectoryTableModel) table.getModel();
		int selectedIndex = table.getSelectedRow();

		int totalTime = 0;
		while ((selectedIndex < 0) && (totalTime < timeoutMillis)) {
			sleep(DEFAULT_WAIT_DELAY);
			totalTime += DEFAULT_WAIT_DELAY;
			selectedIndex = table.getSelectedRow();
		}

		assertTrue(selectedIndex >= 0);
		return dirmodel.getFile(selectedIndex);
	}

	private DirectoryList getListView() {
		return (DirectoryList) findComponentByName(chooser.getComponent(), "LIST");
	}

	private DirectoryTable getTableView() {
		return (DirectoryTable) findComponentByName(chooser.getComponent(), "TABLE");
	}

	private void debugChooser() {
		Msg.debug(this, "Current file chooser state: ");

		// selected file
		File selectedFile = getSelectedFile();
		Msg.debug(this, "\tselected file: " + selectedFile);

		// current directory
		File currentDirectory = getCurrentDirectory();
		Msg.debug(this, "\tcurrent directory: " + currentDirectory);

		// text in text field
		String text = getFilenameFieldText();
		Msg.debug(this, "\tFilename text field text: " + text);

		// files loaded in the table and list
		Msg.debug(this, "\ttable contents: ");
		JTable dirtable = getTableView();
		DirectoryTableModel tableModel = (DirectoryTableModel) dirtable.getModel();
		int size = tableModel.getRowCount();
		for (int i = 0; i < size; i++) {
			Msg.debug(this, "\t\t: " + tableModel.getFile(i));
		}

		Msg.debug(this, "\tlist contents: ");
		DirectoryList dirlist = getListView();
		ListModel<?> model = dirlist.getModel();
		size = model.getSize();
		for (int i = 0; i < size; i++) {
			Msg.debug(this, "\t\t: " + model.getElementAt(i));
		}

	}

	private void cleanupOldTestFiles() {

		// temp test dirs--these contain our test name
		deleteSimilarTempFiles(getName());

		// user dir files
		File[] newFolderFiles = listFiles(homeDir, GhidraFileChooser.NEW_FOLDER);
		for (File file : newFolderFiles) {
			FileUtilities.deleteDir(file);
		}
	}

	private File[] listFiles(File dir, String namePattern) {
		File[] newFolderFiles = homeDir.listFiles((FileFilter) fileToCheck -> {
			if (!fileToCheck.isDirectory()) {
				return false;
			}

			if (!fileToCheck.getName().startsWith(namePattern)) {
				return false;
			}

			return true;
		});
		return ArrayUtils.nullToEmpty(newFolderFiles, File[].class);
	}

	/** Create a temp dir that contains multiple temp dirs and files */
	private TestFiles createMixedDirectory() throws IOException {

		File dir = createTempDirectory("MixedDir");
		TestFiles files = new TestFiles(dir);

		File subdir1 = myCreateTempDirectory(dir, "dir1");
		File subdir2 = myCreateTempDirectory(dir, "dir2");
		File subdir3 = myCreateTempDirectory(dir, "dir3");
		File file1 = myCreateTempFileWithPrefix(dir, "file1");
		File file2 = myCreateTempFileWithPrefix(dir, "file2");
		File file3 = myCreateTempFileWithPrefix(dir, "file3");

		files.parent = dir;
		files.addDirs(subdir1, subdir2, subdir3);
		files.addFiles(file1, file2, file3);

		return files;
	}

	/** Create a temp dir that contains multiple temp dirs and files */
	private TestFiles createAlphabeticMixedDirectory() throws IOException {

		File dir = createTempDirectory("MixedDir");
		TestFiles files = new TestFiles(dir);

		File subdir1 = myCreateTempDirectory(dir, "a_dir1");
		File subdir2 = myCreateTempDirectory(dir, "b_dir2");
		File subdir3 = myCreateTempDirectory(dir, "c_dir3");
		File file1 = myCreateTempFileWithPrefix(dir, "d_file1");
		File file2 = myCreateTempFileWithPrefix(dir, "e_file2");
		File file3 = myCreateTempFileWithPrefix(dir, "f_file3");

		files.parent = dir;
		files.addDirs(subdir1, subdir2, subdir3);
		files.addFiles(file1, file2, file3);

		return files;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	/** Simple container class for newly created dirs and files */
	private class TestFiles {
		private File parent;
		private List<File> dirs = new ArrayList<>();
		private List<File> files = new ArrayList<>();

		TestFiles(File parent) {
			this.parent = parent;
		}

		File randomFile() {
			return random(files);
		}

		File randomDir() {
			return random(dirs);
		}

		private File random(List<File> list) {
			int index = getRandomInt(0, list.size() - 1);
			return list.get(index);
		}

		void addFiles(File... newFiles) {
			files.addAll(Arrays.asList(newFiles));
		}

		void addDirs(File... newDirs) {
			dirs.addAll(Arrays.asList(newDirs));
		}
	}

}
