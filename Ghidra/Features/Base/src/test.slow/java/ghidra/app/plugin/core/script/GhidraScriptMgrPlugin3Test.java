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
package ghidra.app.plugin.core.script;

import static org.junit.Assert.*;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.IOException;

import javax.swing.*;

import org.junit.Test;

import docking.KeyEntryTextField;
import docking.action.DockingActionIf;
import docking.widgets.filter.FilterTextField;
import docking.widgets.list.ListPanel;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.JavaScriptProvider;
import ghidra.util.StringUtilities;
import ghidra.util.exception.AssertException;

public class GhidraScriptMgrPlugin3Test extends AbstractGhidraScriptMgrPluginTest {

	@Test
	public void testKeyBinding() throws Exception {

		selectScript("HelloWorldScript.java");

		int scriptRow = getSelectedRow();

		clearConsole();

		KeyBindingInputDialog kbid = pressKeyBindingAction();

		KeyEntryTextField keyField =
			(KeyEntryTextField) findComponentByName(kbid.getComponent(), "KEY_BINDING");
		triggerActionKey(keyField, InputEvent.SHIFT_DOWN_MASK | InputEvent.ALT_DOWN_MASK,
			KeyEvent.VK_H);
		pressButtonByText(kbid, "OK");

		waitForSwing();

		int columnIndex = indexOfColumn("Key");
		assertEquals("Alt-Shift-H", scriptTable.getValueAt(scriptRow, columnIndex).toString());

		KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_H,
			InputEvent.SHIFT_DOWN_MASK | InputEvent.ALT_DOWN_MASK);
		assertToolKeyBinding(ks);

		// also test trying to set a reserved keybinding
		kbid = pressKeyBindingAction();

		pressButtonByText(kbid, "Cancel");
		waitForSwing();

		assertTrue(!kbid.isShowing());

	}

	@Test
	public void testNewAndEditAndDelete() throws Exception {

		ResourceFile script = createNewScriptUsingGUI();
		assertScriptInTable(script);

		//@formatter:off
		String scriptContents =
				"import ghidra.app.script.GhidraScript;\n\n" +

		    "public class NewScript extends GhidraScript {\n\n" +

		    	"    @Override\n" +
		    	"    public void run() throws Exception {\n" +
		    	"        println(\"new scripts are neato!\");\n" +
		    	"        goTo(toAddr(0x01006420));\n"+
		    	"    }\n\n" +
		    	"}\n\n";
		//@formatter:on

		setScriptEditorContents(scriptContents);

		pressSaveButton();

		String scriptOutput = runSelectedScript(script.getName());

		assertTrue("Script output not generated",
			scriptOutput.contains("> new scripts are neato!"));
		assertFalse("Script output has value from previous test run - did script not get deleted?",
			scriptOutput.contains("Value == 3368601"));

		// verify the 'goto' worked
		assertAtAddress(0x1006420);

		closeEditor();

		pressEditButton();

		//@formatter:off
		String updatedScriptContents =
				"import ghidra.app.script.GhidraScript;\n\n" +

		    "public class NewScript extends GhidraScript {\n\n" +

		    	"    @Override\n" +
		    	"    public void run() throws Exception {\n" +
		    	"        println(\"new scripts are neato!\");\n" +
		    	"        goTo(toAddr(0x01006420));\n"+
		    	"        int val = getInt(toAddr(0x0100b684));\n" +
		    	"        println(\"Value == \"+val);\n" +
		    	"    }\n\n" +
		    	"}\n\n";
		//@formatter:on

		setScriptEditorContents(updatedScriptContents);

		pressSaveButton();
		setTimestampToTheFuture(script);

		String updatedScriptOutput = runSelectedScript(script.getName());

		assertTrue("Script output not updated with new script contents - did recompile work?",
			StringUtilities.containsAll(updatedScriptOutput, "> new scripts are neato!",
				"Value == 3368601"));

		deleteScriptThroughUI();

		assertTrue(!script.exists());
		assertScriptNotInTable(script);
	}

	@Test
	public void testRefreshFindsNewScript() throws Exception {
		int rowCount = getRowCount();

		JavaScriptProvider javaScriptProvider = new JavaScriptProvider();

		ResourceFile newScript = GhidraScriptUtil.createNewScript(javaScriptProvider,
			new ResourceFile(GhidraScriptUtil.USER_SCRIPTS_DIR), provider.getScriptDirectories());
		javaScriptProvider.createNewScript(newScript, null);

		refreshScriptManager();

		assertScriptInScriptManager(newScript);

		assertEquals(rowCount + 1, getRowCount());

		deleteFile(newScript);
	}

	@Test
	public void testRefreshUpdatesCategoriesInTree() throws Exception {
		ResourceFile newScript = createNewScriptUsingGUI();

		refreshScriptManager();

		assertScriptInScriptManager(newScript);

		String newCategory = changeScriptCategory(newScript);
		refreshScriptManager();

		assertCategoryInTree(newCategory);

		String oldCategory = newCategory;
		newCategory = changeScriptCategory(newScript);
		refreshScriptManager();

		assertCategoryInTree(newCategory);
		assertCategoryNotInTree(oldCategory);

		deleteFile(newScript);
	}

	@Test
	public void testRefreshUpdatesCategoriesInTree_WithSubcategories() throws Exception {
		ResourceFile newScript = createNewScriptUsingGUI();

		refreshScriptManager();

		assertScriptInScriptManager(newScript);

		String newCategory = changeScriptCategory_WithSubcatogory(newScript);
		refreshScriptManager();

		assertCategoryInTree(newCategory);

		String oldCategory = newCategory;
		newCategory = changeScriptCategory_WithSubcatogory(newScript);

		refreshScriptManager();

		assertCategoryInTree(newCategory);
		assertCategoryNotInTree(oldCategory);

		deleteFile(newScript);
	}

	@Test
	public void testFilterWithNewAndDelete() throws Exception {

		FilterTextField filterField = getTableFilterField();

		int count = getRowCount();
		runSwing(() -> filterField.setText("write"));
		waitForSwing();

		assertTrue(count != getRowCount());// make sure the filtering is done

		pressNewButton();

		chooseJavaProvider();

		ResourceFile newFile = finishNewScriptDialog();
		assertScriptInTable(newFile);

		deleteScriptThroughUI();

		assertScriptNotInTable(newFile);
	}

	@Test
	public void testDeleteWhenThatScriptIsTheOnlyOneFiltered() throws Exception {

		FilterTextField filterField = getTableFilterField();

		String newScriptName = "Script" + System.currentTimeMillis() + ".java";
		runSwing(() -> filterField.setText(newScriptName));
		waitForSwing();

		assertEquals(0, getRowCount());

		pressNewButton();

		chooseJavaProvider();

		ResourceFile newFile = finishNewScriptDialog(newScriptName);
		assertScriptInTable(newFile);

		deleteScriptThroughUI();

		assertScriptNotInTable(newFile);

		assertEquals(0, getRowCount());
	}

	@Test
	public void testNewInCategory() throws Exception {

		String category = "Memory";
		selectCategory(category);

		ResourceFile newScript = createNewScriptUsingGUI();

		assertScriptSelected(newScript);
		assertScriptCategory(newScript, category);
	}

	@Test
	public void testNewWithPaths() throws Exception {
		//
		// Tests that the user can add an additional script path directory and choose that one
		// to use
		//
		DockingActionIf bundleStatusAction = getAction(plugin, "Script Directories");
		performAction(bundleStatusAction, false);
		waitForSwing();

		final ResourceFile dir = new ResourceFile(getTestDirectoryPath() + "/test_scripts");
		dir.getFile(false).mkdirs();

		provider.getBundleHost().enable(dir);
		waitForSwing();

		pressNewButton();

		chooseJavaProvider();

		SaveDialog saveDialog = waitForDialogComponent(SaveDialog.class);

		final ListPanel listPanel = (ListPanel) findComponentByName(saveDialog.getComponent(), "PATH_LIST");
		assertNotNull(listPanel);
		assertTrue(listPanel.isVisible());
		assertEquals(2, listPanel.getListModel().getSize());
		runSwing(() -> {
			StringBuilder buffy = new StringBuilder();
			JList<?> list = listPanel.getList();
			ListModel<?> model = list.getModel();
			int size = model.getSize();
			for (int i = 0; i < size; i++) {
				Object item = model.getElementAt(i);
				buffy.append(item.toString()).append('\n');
				if (item.toString().equals(dir.getAbsolutePath())) {
					list.setSelectedIndex(i);
					return;
				}
			}

			throw new AssertException("Unable to find our newly added script directory: " + dir +
				"\nInstead we found: " + buffy.toString());
		}, false);
		waitForSwing();

		pressButtonByText(saveDialog, "OK");
		assertTrue(!saveDialog.isShowing());
		waitForTasks();

		ResourceFile newScript = saveDialog.getFile();
		assertTrue(newScript.exists());

		assertNotNull(newScript);
		assertEquals(dir.getAbsolutePath(),
			newScript.getParentFile().getFile(false).getAbsolutePath());

		deleteFile(newScript);
		deleteFile(dir);
		waitForSwing();
	}

	@Test
	public void testNewScriptDoesNotOverwriteExistingScriptOnDiskThatScriptManagerDoesNotYetKnowAbout()
			throws Exception {

		//
		// In this scenario the script manager does not 'know' about the script in question
		// since we have created it 'behind the scenes'
		//

		ResourceFile tempScriptFile = createTempScriptFile();
		String scriptName = tempScriptFile.getName();

		assertCannotCreateNewScriptByName(scriptName);
	}

	@Test
	public void testNewScriptWithSameNameAsScriptInEditorWhenEditorsFileOnDiskIsDeleted()
			throws Exception {

		//
		// In this scenario the script manager does not 'know' about the script being deleted
		// because we did not tell the manager to refresh after deleting.
		//

		ResourceFile firstScript = createNewScriptUsingGUI();
		String firstScriptName = firstScript.getName();
		String originalContents = readFileContents(firstScript);

		deleteFile(firstScript);

		assertEditorContentsSame(originalContents);

		assertCannotCreateNewScriptByName(firstScriptName);
	}

	@Test
	public void testRefreshOnEditor() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		String originalContents = readFileContents(script);

		pressRefreshButton();

		assertEditorContentsSame(originalContents);
	}

	@Test
	public void testRefreshCleanEditor_FileOnDiskIsDeleted_Discard() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		deleteFile(script);

		pressRefreshButton();

		chooseDiscaredEditorChanges();

		assertFalse("Editor not closed after discarding changes", editor.isVisible());

	}

	@Test
	public void testRefreshDirtyEditor_No_ChangesOnDisk() throws IOException {
		loadTempScriptIntoEditor();

		String changedContents = changeEditorContents();

		pressRefreshButton();

		assertEditorContentsSame(changedContents);
	}

	@Test
	public void testRefreshDirtyEditor_ChangesOnDisk_OverwiteDiskFile() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		String changedContents = changeEditorContents();
		changeFileOnDisk(script);

		pressRefreshButton();
		chooseOverwriteFileOnDisk();

		assertEditorContentsSame(changedContents);
		assertFileSaved(script, changedContents);
	}

	@Test
	public void testRefreshDirtyEditor_ChangesOnDisk_DiscardEditorChanges() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		changeEditorContents();
		String newDiskContents = changeFileOnDisk(script);

		pressRefreshButton();
		chooseDiscaredEditorChanges();

		assertEditorContentsSame(newDiskContents);
	}

	@Test
	public void testRefreshDirtyEditor_ChangesOnDisk_Cancel() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		String changedContents = changeEditorContents();
		changeFileOnDisk(script);

		pressRefreshButton();
		chooseCancel();

		assertEditorContentsSame(changedContents);
	}

	@Test
	public void testRefreshDirtyEditor_ChangesOnDisk_SaveAs() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		String changedContents = changeEditorContents();
		String newDiskContents = changeFileOnDisk(script);

		pressRefreshButton();

		ResourceFile newFile = chooseSaveAs();

		assertFileSaved(newFile, changedContents);
		assertFileInEditor(script, newFile);
		assertEditorContentsSame(script, newDiskContents);
		assertEditorContentsSame(newFile, changedContents);
	}

	@Test
	public void testRefreshDirtyEditor_FileOnDiskIsDeleted_SaveAs() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		String changedContents = changeEditorContents();

		deleteFile(script);

		pressRefreshButton();

		ResourceFile newFile = chooseSaveAs_ForMissingFile();

		assertFileSaved(newFile, changedContents);
		assertEditorContentsSame(newFile, changedContents);
	}

	@Test
	public void testRefreshDirtyEditor_FileOnDiskIsDeleted_Cancel() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		String changedContents = changeEditorContents();

		deleteFile(script);

		pressRefreshButton();

		chooseCancel_ForMissingFile();

		assertEditorContentsSame(changedContents);
	}

	@Test
	public void testRefreshUnchangedEditor_ChangesOnDisk() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		String diskContents = changeFileOnDisk(script);

		pressRefreshButton();

		assertEditorContentsSame(diskContents);
	}

	@Test
	public void testRefreshUnchangedEditor_FileOnDiskIsDeleted_Cancel() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		deleteFile(script);

		pressRefreshButton();

		chooseCancel_ForMissingFile();
	}

	@Test
	public void testRefreshUnchangedEditor_FileOnDiskIsDeleted_SaveAs() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		String originalContents = readFileContents(script);

		deleteFile(script);

		pressRefreshButton();

		ResourceFile newFile = chooseSaveAs_ForMissingFile();

		assertFileSaved(newFile, originalContents);
		assertEditorContentsSame(newFile, originalContents);
	}

	@Test
	public void testCancel() throws Exception {
		TestChangeProgramScript script = startCancellableScriptTask();

		cancel();

		cancel_Yes(script);
	}

	@Test
	public void testCancel_DoNotCancel() throws Exception {
		TestChangeProgramScript script = startCancellableScriptTask();

		cancel();

		cancel_No(script);
	}
}
