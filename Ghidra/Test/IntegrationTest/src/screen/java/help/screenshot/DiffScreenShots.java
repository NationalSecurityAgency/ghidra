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
package help.screenshot;

import java.awt.Color;
import java.awt.Font;

import javax.swing.*;

import org.junit.Test;

import docking.ComponentProvider;
import docking.DialogComponentProvider;
import ghidra.app.nav.ListingPanelContainer;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.services.ProgramManager;
import ghidra.framework.main.OpenVersionedFileDialog;
import ghidra.framework.main.datatree.DataTree;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;

public class DiffScreenShots extends GhidraScreenShotGenerator {
	private static TaskMonitor dummyMonitor = TaskMonitor.DUMMY;

	@Test
	public void testSelectOtherProgram() throws Exception {
		addProgramsToProject();
		program = env.getProgram("WinHelloCPP.exe");
		performAction("Open/Close Program View", "ProgramDiffPlugin", false);
		performAction("Open/Close Program View", "ProgramDiffPlugin", false);
		waitForSwing();
		DialogComponentProvider dialog = getDialog();
		captureDialog(dialog.getPreferredSize().width, 500);

	}

	@Test
	public void testSelectOtherVersionedProgram() throws Exception {

		addProgramsToProject();
		createProgramVersions();
		waitForSwing();
		performAction("Open/Close Program View", "ProgramDiffPlugin", false);
		performAction("Open/Close Program View", "ProgramDiffPlugin", false);
		waitForSwing();
		OpenVersionedFileDialog dialog = (OpenVersionedFileDialog) getDialog();
		DataTree dataTree = (DataTree) findComponentByName(dialog.getComponent(), "Data Tree");
		selectPath(dataTree, env.getProject().getName(), "WinHelloCpp.exe");
		JButton historyButton = findButtonByText(dialog.getComponent(), "History>>");
		pressButton(historyButton);
		captureDialog();
	}

	@Test
	public void testDetermineDiffs() throws Exception {
		addProgramsToProject();
		performAction("Open/Close Program View", "ProgramDiffPlugin", false);
		performAction("Open/Close Program View", "ProgramDiffPlugin", false);
		waitForSwing();
		OpenVersionedFileDialog dialog = (OpenVersionedFileDialog) getDialog();
		DataTree dataTree = (DataTree) findComponentByName(dialog.getComponent(), "Data Tree");
		selectPath(dataTree, env.getProject().getName(), "WinHelloCpp.exe");
		waitForSwing();
		pressButtonByText(dialog.getComponent(), "OK", false);
		waitForSwing();
		captureDialog();
	}

	@Test
	public void testDiff() throws Exception {
		addProgramsToProject();
		createDifferences();
		performAction("Open/Close Program View", "ProgramDiffPlugin", false);
		performAction("Open/Close Program View", "ProgramDiffPlugin", false);
		waitForSwing();
		OpenVersionedFileDialog dialog = (OpenVersionedFileDialog) getDialog();
		DataTree dataTree = (DataTree) findComponentByName(dialog.getComponent(), "Data Tree");
		selectPath(dataTree, env.getProject().getName(), "WinHelloCpp.exe");
		waitForSwing();
		pressButtonByText(dialog.getComponent(), "OK", false);
		waitForSwing();
		pressButtonByText(getDialog().getComponent(), "OK", false);
		waitForBusyTool(tool);
		evenDiffWindow();
		nextDiff();
		nextDiff();
		goToListing(0x408dd9);
		captureProvider(CodeViewerProvider.class);
	}

	@Test
	public void testDiffApplySettings() throws Exception {
		addProgramsToProject();
		createDifferences();
		performAction("Open/Close Program View", "ProgramDiffPlugin", false);
		performAction("Open/Close Program View", "ProgramDiffPlugin", false);
		waitForSwing();
		OpenVersionedFileDialog dialog = (OpenVersionedFileDialog) getDialog();
		DataTree dataTree = (DataTree) findComponentByName(dialog.getComponent(), "Data Tree");
		selectPath(dataTree, env.getProject().getName(), "WinHelloCpp.exe");
		waitForSwing();
		pressButtonByText(dialog.getComponent(), "OK", false);
		waitForSwing();
		pressButtonByText(getDialog().getComponent(), "OK", false);
		waitForBusyTool(tool);
		evenDiffWindow();
		nextDiff();
		nextDiff();
		goToListing(0x408dd9);
		performAction("Show Diff Apply Settings", "ProgramDiffPlugin", true);
		ComponentProvider provider = getProvider("Diff Apply Settings");
		captureIsolatedProvider(provider.getClass(), 1100, 260);
	}

	@Test
	public void testDiffApplySettingsPopup() throws Exception {
		JMenu jMenu = new JMenu();
		Font font = jMenu.getFont().deriveFont(11f);
		TextFormatter tf = new TextFormatter(font, 3, 220, 0, 20, 3);
		TextFormatterContext white = new TextFormatterContext(Color.WHITE);
		tf.colorLines(new Color(60, 115, 200), 2, 1);

		tf.writeln("Set Ignore for All Apply Settings");
		tf.writeln("Set Replace for All Apply Settings");
		tf.writeln("|Set Merge for All Apply Settings|", white);
		image = tf.getImage();
	}

	@Test
	public void testDiffDetails() throws Exception {
		addProgramsToProject();
		createDifferencesAt401417();
		performAction("Open/Close Program View", "ProgramDiffPlugin", false);
		performAction("Open/Close Program View", "ProgramDiffPlugin", false);
		waitForSwing();
		OpenVersionedFileDialog dialog = (OpenVersionedFileDialog) getDialog();
		DataTree dataTree = (DataTree) findComponentByName(dialog.getComponent(), "Data Tree");
		selectPath(dataTree, env.getProject().getName(), "WinHelloCpp.exe");
		waitForSwing();
		pressButtonByText(dialog.getComponent(), "OK", false);
		waitForSwing();
		pressButtonByText(getDialog().getComponent(), "OK", false);
		waitForBusyTool(tool);
		evenDiffWindow();
		nextDiff();
		performAction("Diff Location Details", "ProgramDiffPlugin", true);
		ComponentProvider provider = getProvider("Diff Location Details");
		captureIsolatedProvider(provider.getClass(), 510, 350);
	}

	private void nextDiff() {
		runSwing(() -> {
			Plugin plugin = getPluginByName(tool, "ProgramDiffPlugin");
			invokeInstanceMethod("nextDiff", plugin);
		});
	}

	private void evenDiffWindow() {
		runSwing(() -> {
			CodeViewerProvider provider = getProvider(CodeViewerProvider.class);
			ListingPanelContainer container = (ListingPanelContainer) provider.getComponent();
			JSplitPane splitPane = (JSplitPane) getInstanceField("splitPane", container);
			splitPane.setDividerLocation(0.5);
		});

	}

	private void createProgramVersions() throws Exception {
		Project project = env.getProject();
		ProjectData projectData = project.getProjectData();
		DomainFile file = projectData.getRootFolder().getFile("WinHelloCpp.exe");
		file.addToVersionControl("First Version", true, dummyMonitor);
	}

	private void addProgramsToProject() throws Exception {
		program = env.getProgram("WinHelloCPP.exe");
		Project project = env.getProject();
		ProjectData projectData = project.getProjectData();
		projectData.getRootFolder().createFile("WinHelloCpp.exe", program, TaskMonitor.DUMMY);
		projectData.getRootFolder().createFile("OldWinHelloCpp.exe", program, TaskMonitor.DUMMY);
		waitForSwing();
	}

	private void createDifferences() throws Exception {
		Project project = env.getProject();
		ProjectData projectData = project.getProjectData();
		DomainFile file = projectData.getRootFolder().getFile("WinHelloCpp.exe");
		Program p = (Program) file.getDomainObject(this, false, false, dummyMonitor);
		int id = p.startTransaction("Test");

		Listing listing = p.getListing();
		listing.clearCodeUnits(addr(0x408dcd), addr(0x408dcd), false);
		SymbolTable symbolTable = p.getSymbolTable();
		symbolTable.createLabel(addr(0x408dd9), "BOB", SourceType.USER_DEFINED);
		symbolTable.createLabel(addr(0x408deb), "EXTRA", SourceType.USER_DEFINED);

		p.endTransaction(id, true);
		p.save("some changes", dummyMonitor);
		p.release(this);
	}

	private void createDifferencesAt401417() throws Exception {
		Address addr = addr(0x401417);
		Project project = env.getProject();
		ProjectData projectData = project.getProjectData();
		DomainFile file = projectData.getRootFolder().getFile("WinHelloCpp.exe");
		Program p = (Program) file.getDomainObject(this, false, false, dummyMonitor);
		int id = p.startTransaction("Test");

		Function function = p.getFunctionManager().getFunctionContaining(addr);
		SymbolTable symbolTable = p.getSymbolTable();
		symbolTable.createLabel(addr, "MyLabel", function, SourceType.USER_DEFINED);

		p.endTransaction(id, true);
		p.save("some changes", dummyMonitor);
		p.release(this);

		// now make a similar change in the current program, but use the global namespace
		ProgramManager service = tool.getService(ProgramManager.class);
		p = service.getCurrentProgram();
		id = p.startTransaction("Test");
		symbolTable = p.getSymbolTable();
		symbolTable.createLabel(addr, "MyLabel", SourceType.USER_DEFINED);
		p.endTransaction(id, true);
	}
}
