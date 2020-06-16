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

import java.io.*;

import org.apache.logging.log4j.*;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.table.SelectionManager;
import generic.jar.ResourceFile;
import generic.test.AbstractGTest;
import ghidra.app.plugin.core.osgi.GhidraSourceBundle;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.JavaScriptProvider;
import ghidra.test.ScriptTaskListener;
import ghidra.util.TaskUtilities;
import utilities.util.FileUtilities;

public class GhidraScriptMgrPlugin2Test extends AbstractGhidraScriptMgrPluginTest {

	public GhidraScriptMgrPlugin2Test() {
		super();
	}

	@Test
	public void testRun() throws Exception {
		//
		// Test running by using the run action with a table selection in the GUI
		//
		String scriptName = "HelloWorldScript.java";
		selectScript(scriptName);
		TaskListenerFlag taskFlag = new TaskListenerFlag(scriptName);
		TaskUtilities.addTrackedTaskListener(taskFlag);

		pressRunButton();
		waitForTaskEnd(taskFlag);

		String consoleText = getConsoleText();
		assertTrue("ConsoleText was \"" + consoleText + "\".",
			consoleText.indexOf("> Hello World") >= 0);

	}

	@Test
	public void testScriptWithInnerClassAndLocalClass() throws Exception {
		ResourceFile innerScriptFile = createInnerClassScript();

		String output = runScriptAndGetOutput(innerScriptFile);

		assertTrue("Inner class output not found", output.indexOf("I am an inner class") != -1);
		assertTrue("External class output not found",
			output.indexOf("I am an external class") != -1);
	}

	@Test
	public void testScriptRecompileWithAbstractParent_ChangeOnlyParent() throws Exception {
		//
		// Test that if a user uses a parent class other than GhidraScript, that parent
		// class will get recompiled when it changes.
		//

		ResourceFile parentScriptFile = createTempScriptFile("AbstractParentScript");

		String v1Message = "Hello from version 1";
		writeAbstractScriptContents(parentScriptFile, v1Message);

		ResourceFile childScriptFile = createChildScript(parentScriptFile, null);

		String output = runScriptAndGetOutput(childScriptFile);

		assertContainsText(v1Message, output);

		// change the parent script
		String v2Message = "Hello from version 2";
		writeAbstractScriptContents(parentScriptFile, v2Message);

		output = runScriptAndGetOutput(childScriptFile);

		assertContainsText(v2Message, output);
	}

	@Test
	public void testScriptWithParentInPackageRecompile() throws Exception {
		final String parentName = "ParentInPackageScript";
		final String packageName = parentName + "Pkg";

		ResourceFile parentScriptFile = createTempScriptFile(parentName, packageName);
		writePackageScriptContents(parentScriptFile, packageName);

		ResourceFile childScriptFile = createChildScript(parentScriptFile, packageName);

		String output = runScriptAndGetOutput(childScriptFile);
		assertContainsText("0", output);
		output = runScriptAndGetOutput(childScriptFile);
		assertContainsText("1", output);

		// Change the parent script so it recompiles and resets its static state
		Thread.sleep(1000); // Ensure our file write advances the last modified timestamp
		writePackageScriptContents(parentScriptFile, packageName);
		output = runScriptAndGetOutput(childScriptFile);
		assertContainsText("0", output);
	}

	@Test
	public void testScriptsCompileToBinDirectory() throws Exception {
		//
		// Test that compiling a script to the user's script dir will use a bin dir for the
		// output.
		//
		// create a new dummy script
		File userScriptsDir = new File(GhidraScriptUtil.USER_SCRIPTS_DIR);
		String rawScriptName = testName.getMethodName();
		String scriptFilename = rawScriptName + ".java";
		File newScriptFile = new File(userScriptsDir, scriptFilename);
		if (newScriptFile.exists()) {
			assertTrue("Unable to delete script file for testing: " + newScriptFile,
				newScriptFile.delete());
		}

		JavaScriptProvider scriptProvider = new JavaScriptProvider();
		scriptProvider.createNewScript(new ResourceFile(newScriptFile), null);

		// remove all class files from the user script dir (none should ever be there)
		FileFilter classFileFilter = file -> file.getName().endsWith(".class");
		File[] userScriptDirFiles = userScriptsDir.listFiles(classFileFilter);
		for (File file : userScriptDirFiles) {
			file.delete();
		}
		userScriptDirFiles = userScriptsDir.listFiles(classFileFilter);
		boolean isEmpty = userScriptDirFiles == null || userScriptDirFiles.length == 0;
		assertTrue("Unable to delete class files from the user scripts directory", isEmpty);

		// remove all class files from the user script bin dir
		File userScriptsBinDir =
			GhidraSourceBundle.getBindirFromScriptFile(new ResourceFile(newScriptFile)).toFile();
		File[] userScriptBinDirFiles;
		if (userScriptsBinDir.exists()) {
			userScriptBinDirFiles = userScriptsBinDir.listFiles(classFileFilter);
			for (File file : userScriptBinDirFiles) {
				file.delete();
			}
		}
		userScriptBinDirFiles = userScriptsDir.listFiles(classFileFilter);
		isEmpty = userScriptBinDirFiles == null || userScriptBinDirFiles.length == 0;
		assertTrue("Unable to delete class files from the bin directory", isEmpty);

		// compile the script
		ScriptTaskListener scriptID = env.runScript(newScriptFile);
		waitForScriptCompletion(scriptID, 20000);

		// make sure the class file is in the user dir's bin dir
		assertTrue("bin dir was not created!", userScriptsBinDir.exists());
		File classFile = new File(userScriptsBinDir, rawScriptName + ".class");
		assertTrue("Class file was not compiled to the bin dir", classFile.exists());

		// make sure no other class files are in the user script dir
		userScriptDirFiles = userScriptsDir.listFiles(classFileFilter);
		isEmpty = userScriptDirFiles == null || userScriptDirFiles.length == 0;
		assertTrue("Class files were written to the top level script directory", isEmpty);

		newScriptFile.delete();
	}

	@Test
	public void testSystemScriptsCompileToDefaultBinDirectory() throws Exception {
		//
		// Tests that a system script will not get compiled to the source tree in which it lives,
		// but will instead get compiled to the user scripts directory
		//
		// find a system script
		String scriptName = "HelloWorldScript.java";
		ResourceFile systemScriptFile = findScript(scriptName);

		// compile the system script
		ScriptTaskListener scriptID = env.runScript(systemScriptFile.getFile(false));
		waitForScriptCompletion(scriptID, 20000);

		// verify that the generated class file is placed in the default scripting home/bin
		File userScriptsBinDir =
			GhidraSourceBundle.getBindirFromScriptFile(systemScriptFile).toFile();
		String className = scriptName.replace(".java", ".class");
		File expectedClassFile = new File(userScriptsBinDir, className);

		assertTrue("System script not compiled to the expected directory",
			expectedClassFile.exists());
	}

	@Test
	public void testUserDefinedScriptsWillCompileToUserDefinedDirectory() throws Exception {
		//
		// Tests that we can create a user-defined scripts directory and that compiling a
		// script will put the output in the bin directory under the user settings directory.
		//
		// create a user-defined directory
		File tempDir = new File(AbstractGTest.getTestDirectoryPath());
		File tempScriptDir = new File(tempDir, "TestScriptDir");
		FileUtilities.deleteDir(tempScriptDir);
		tempScriptDir.mkdir();

		ResourceFile scriptDir = new ResourceFile(tempScriptDir);
		provider.getBundleHost().enable(scriptDir);

		try {
			// create a script file in that directory
			String rawScriptName = testName.getMethodName();
			String scriptFilename = rawScriptName + ".java";
			ResourceFile newScriptFile = new ResourceFile(scriptDir, scriptFilename);

			JavaScriptProvider scriptProvider = new JavaScriptProvider();
			scriptProvider.createNewScript(newScriptFile, null);

			// compile the script
			ScriptTaskListener scriptID = env.runScript(newScriptFile.getFile(false));
			waitForScriptCompletion(scriptID, 20000);

			// verify a bin dir was created and that the class file is in it
			File binDir = GhidraSourceBundle.getBindirFromScriptFile(newScriptFile).toFile();
			assertTrue("bin output dir not created", binDir.exists());

			File scriptClassFile = new File(binDir, rawScriptName + ".class");
			assertTrue("Script not compiled to the user-defined script directory",
				scriptClassFile.exists());

			deleteFile(newScriptFile);
		}
		finally {
			deleteFile(scriptDir);
		}
	}

	@Test
	public void testRenameWithTreeFilter() throws Exception {

		// debug
		Logger logger = LogManager.getLogger(SelectionManager.class);
		Configurator.setLevel(logger.getName(), Level.TRACE);

		pressNewButton();

		chooseJavaProvider();

		SaveDialog saveDialog = AbstractDockingTest.waitForDialogComponent(SaveDialog.class);
		pressButtonByText(saveDialog, "OK");

		refreshProvider();

		int row = getSelectedRow();
		assertTrue("New script was not selected after refresh", row >= 0);

		ResourceFile oldScript = provider.getScriptAt(row);
		assertNotNull(oldScript);

		selectCategory("_NEW_");

		assertScriptInTable(oldScript);

		selectScript(oldScript);

		closeEditor();

		pressRenameButton();

		String newName = "Temp" + System.currentTimeMillis() + ".java";
		ResourceFile newScript = finishNewScriptDialog(newName);

		assertScriptSelected(newScript);
		assertScriptManagerForgotAbout(oldScript);
		assertScriptManagerKnowsAbout(newScript);

		deleteFile(newScript);
	}

	@Test
	public void testRenameScriptDoesNotOverwriteExistingScriptOnDiskThatScriptManagerDoesNotYetKnowAbout()
			throws Exception {

		ResourceFile firstScript = createNewScriptUsingGUI();
		String originalContents = readFileContents(firstScript);

		deleteFile(firstScript);

		assertEditorContentsSame(originalContents);

		assertCannotRefresh();
	}

	@Test
	public void testSaveDirtyEditor_No_ChangesOnDisk() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		String changedContents = changeEditorContents();

		pressSaveButton();

		assertFileSaved(script, changedContents);
	}

	@Test
	public void testSaveDirtyEditor_ChangesOnDisk_OverwiteDiskFile() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		String newContents = changeEditorContents();
		changeFileOnDisk(script);

		pressSaveButton();

		chooseOverwriteFileOnDisk();

		assertFileSaved(script, newContents);
	}

	@Test
	public void testSaveDirtyEditor_ChangesOnDisk_DiscardEditorChanges() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		changeEditorContents();
		String diskChanges = changeFileOnDisk(script);

		pressSaveButton();
		chooseDiscaredEditorChanges();

		assertEditorContentsSame(diskChanges);
	}

	@Test
	public void testSaveDirtyEditor_ChangesOnDisk_Cancel() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		String changedContents = changeEditorContents();
		String diskChanges = changeFileOnDisk(script);

		pressSaveButton();
		chooseCancel();

		assertEditorContentsSame(changedContents);
		assertFileContentsSame(diskChanges, script);
	}

	@Test
	public void testSaveDirtyEditor_ChangesOnDisk_SaveAs() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		String changedContents = changeEditorContents();
		changeFileOnDisk(script);

		pressSaveButton();
		ResourceFile newFile = chooseSaveAs();

		assertFileSaved(newFile, changedContents);
		assertFileInEditor(script, newFile);
	}

	@Test
	public void testSaveDirtyEditor_FileOnDiskIsDeleted() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();

		String changedContents = changeEditorContents();

		deleteFile(script);

		pressSaveButton();

		assertFileSaved(script, changedContents);
		assertFileInEditor(script);

		deleteFile(script);
	}

	@Test
	public void testSaveAsDoesNotAllowOverwriteExistingFileThatScriptManagerDoesNotYetKnowAbout()
			throws Exception {
		//
		// In this scenario the script manager does not 'know' about the script in question
		// since we have created it 'behind the scenes'
		//

		ResourceFile notYetKnownScript = createTempScriptFile();
		String notYetKnownScriptName = notYetKnownScript.getName();

		loadTempScriptIntoEditor();

		assertCannotPerformSaveAsByName(notYetKnownScriptName);
	}

	@Test
	public void testSaveAsDoesNotAllowUseOfExistingScriptName() throws Exception {
		ResourceFile existingScript = createTempScriptFile();
		refreshProvider();// alert manager to new script

		loadTempScriptIntoEditor();

		assertCannotPerformSaveAsByNameDueToDuplicate(existingScript.getName());
		deleteFile(existingScript);
	}

	@Test
	public void testSaveAsDoesNotAllowUseOfExistingSystemScriptName() throws Exception {
		ResourceFile systemScript = findScript("HelloWorldScript.java");

		loadTempScriptIntoEditor();

		assertCannotPerformSaveAsByNameDueToDuplicate(systemScript.getName());
	}

	@Test
	public void testSaveAsAllowsUseOfDeletedScriptName() throws Exception {
		//
		// Tests that the user *can* pick the name of a script that is in the script manager,
		// *if that script no longer exists on disk*
		//
		ResourceFile existingScript = createTempScriptFile();
		refreshProvider();// alert manager to new script

		loadTempScriptIntoEditor();

		deleteFile(existingScript);

		assertSaveAs(existingScript.getName());
	}

	@Test
	public void testSaveButtonEnablement() throws Exception {
		loadTempScriptIntoEditor();
		assertSaveButtonDisabled();

		changeEditorContents();

		assertSaveButtonEnabled();

		pressSaveButton();

		assertSaveButtonDisabled();
	}

	@Test
	public void testSaveButtonEnablementAfterRefresh() throws IOException {
		ResourceFile script = loadTempScriptIntoEditor();
		assertSaveButtonDisabled();

		changeFileOnDisk(script);

		assertSaveButtonDisabled();

		pressRefreshButton();

		assertSaveButtonDisabled();
	}

	@Test
	public void testScriptInstancesAreNotReused() throws Exception {
		//
		// Checks for the error where script fields accumulated state because script
		// instances were reused.  Script instances should be recreated for each run.
		//
		ResourceFile script = createInstanceFieldScript();
		String output = runScriptAndGetOutput(script);
		assertContainsText("*1*", output);

		output = runScriptAndGetOutput(script);
		assertContainsText("The field of the script still has state--the script was not recreated",
			"*1*", output);
	}

	@Test
	public void testStaticVariableSupport() throws Exception {
		//
		// If the script is not changed, do not reload, which allows for clients to use
		// static variables to maintain state.
		//
		ResourceFile script = createStaticFieldScript();
		String output = runScriptAndGetOutput(script);
		assertContainsText("*1*", output);

		output = runScriptAndGetOutput(script);
		assertContainsText("The field of the script still has state--the script was not recreated",
			"*2*", output);
	}
}
