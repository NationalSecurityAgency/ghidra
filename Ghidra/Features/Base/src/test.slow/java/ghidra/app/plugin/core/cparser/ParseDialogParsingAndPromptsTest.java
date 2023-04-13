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
package ghidra.app.plugin.core.cparser;

import static org.junit.Assert.*;

import java.awt.Window;
import java.io.File;
import java.util.ArrayList;

import javax.swing.JTextArea;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.pathmanager.PathnameTablePanel;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.cparser.ParseDialog.ComboBoxItem;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.processors.SetLanguageDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.plugin.importer.NewLanguagePanel;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.test.*;
import utilities.util.FileUtilities;

public class ParseDialogParsingAndPromptsTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String TITLE = "CParser Results Summary";

	private TestEnv env;
	private PluginTool tool;

	private Program program;
	private CParserPlugin plugin;

	private DockingActionIf cparserAction;
	
	private DataTypeManagerPlugin dtmPlugin;
	

	@Before
	public void setUp() throws Exception {
		program = getNotepad();
		
		env = new TestEnv();
	}

	private Program getNotepad() throws Exception {
		ClassicSampleX86ProgramBuilder builder =
			new ClassicSampleX86ProgramBuilder("notepad", false, this);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	private void initTool(Program prog) throws Exception {
		if (prog != null) {
			tool = env.showTool(prog);
		} else {
			tool = env.showTool();
		}

		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(CParserPlugin.class.getName());
		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		plugin = getPlugin(tool, CParserPlugin.class);

		cparserAction = getAction(plugin, CParserPlugin.PARSE_ACTION_NAME);
		dtmPlugin = getPlugin(tool, DataTypeManagerPlugin.class);
	}

	@Test
	public void testImportToProgramNoneOpen() throws Exception {
		initTool(null);

		ParseDialog parseDialog = showParseDialog();
		
		this.setSelectedParseProfile(parseDialog, "VisualStudio12_32.prf");

		pressButtonByText(parseDialog, "Parse to Program", false);
		
		pressButtonByText(waitForDialogComponent("No Open Program"), "OK", false);
		
	}

	@Test
	public void testImportToProgramNoArch() throws Exception {
		program = getNotepad();
		
		initTool(program);

		ParseDialog parseDialog = showParseDialog();

		this.setSelectedParseProfile(parseDialog, "MacOSX_10.5.prf");
		
		pressButtonByText(parseDialog, "Parse to Program", false);
		
		String langText = parseDialog.getLanguageText().getText();
		assertEquals("64/32 (primarily for backward compatibility)", langText);

		pressButtonByText(waitForDialogComponent("Program Architecture not Specified"), "OK", false);
	}
	
	@Test
	public void testImportToProgramConfirm() throws Exception {
		program = getNotepad();
		
		initTool(program);

		ParseDialog parseDialog = showParseDialog();

		this.setSelectedParseProfile(parseDialog, "VisualStudio12_32.prf");
		
		pressButtonByText(parseDialog, "Parse to Program", false);

		pressButtonByText(waitForDialogComponent("Confirm"), "Cancel", false);
	}
	
	@Test
	public void testImportToProgram() throws Exception {

		initTool(program);

		ParseDialog parseDialog = showParseDialog();

		this.setSelectedParseProfile(parseDialog, "VisualStudio12_32.prf");
		
		// write out a dummy header file to read
		File dummyHeader = this.createTempFile("dummy.h");
		
		FileUtilities.deleteDir(dummyHeader);
		
		String files[] = {dummyHeader.getPath()};
		
		this.setFiles(parseDialog, files);
		
		pressButtonByText(parseDialog, "Parse to Program", false);
		
		pressButtonByText(waitForDialogComponent("Confirm"), "Continue", false);
		
		// dummy file empty, error
		pressButtonByText(waitForDialogComponent("Parse Errors"), "OK", false);
		
		// dummy file full, OK
		FileUtilities.writeStringToFile(dummyHeader,
	        "typedef int wchar_t;\n" +
	        "struct mystruct {\n" +
	        "    wchar_t defined_wchar_t;\n" +
	        "};\n");
		
		this.setFiles(parseDialog, files);

		pressButtonByText(parseDialog, "Parse to Program", false);
		
		pressButtonByText(waitForDialogComponent("Confirm"), "Continue", false);
		
		waitForBusyTool(tool);

		pressButtonByText(waitForDialogComponent("C-Parse of Header Files Complete"), "OK", false);
		
		DataType dataType = program.getDataTypeManager().getDataType("/"+dummyHeader.getName()+ "/" + "mystruct");
		
		assertNotNull("mystruct parsed into program", dataType);
	}
	
	@Test
	public void testImportToProgramWithIncludePaths() throws Exception {

		initTool(program);

		ParseDialog parseDialog = showParseDialog();

		this.setSelectedParseProfile(parseDialog, "VisualStudio12_32.prf");
		
		// write out a dummy header file to read
		File dummyHeader = this.createTempFile("dummy.h");
		
		FileUtilities.deleteDir(dummyHeader);
		
		String files[] = {dummyHeader.getName()};
		
		this.setFiles(parseDialog, files);
		
		String includePath[] = {dummyHeader.getParent()};
		
		this.setIncludePaths(parseDialog, includePath);
		
		pressButtonByText(parseDialog, "Parse to Program", false);
		
		pressButtonByText(waitForDialogComponent("Confirm"), "Continue", false);
		
		// dummy file empty, error
		pressButtonByText(waitForDialogComponent("Parse Errors"), "OK", false);
		
		// dummy file full, OK
		FileUtilities.writeStringToFile(dummyHeader,
	        "typedef int wchar_t;\n" +
	        "struct mystruct {\n" +
	        "    wchar_t defined_wchar_t;\n" +
	        "};\n");
		
		this.setFiles(parseDialog, files);

		pressButtonByText(parseDialog, "Parse to Program", false);
		
		pressButtonByText(waitForDialogComponent("Confirm"), "Continue", false);
		
		waitForBusyTool(tool);

		pressButtonByText(waitForDialogComponent("C-Parse of Header Files Complete"), "OK", false);
		
		DataType dataType = program.getDataTypeManager().getDataType("/"+dummyHeader.getName()+ "/" + "mystruct");
		
		assertNotNull("mystruct parsed into program", dataType);
	}
	
	@Test
	public void testImportToProgramOpenArchives() throws Exception {
		initTool(program);

		ParseDialog parseDialog = showParseDialog();
		
		// open an archive
		dtmPlugin.openDataTypeArchive("windows_vs12_64");

		this.setSelectedParseProfile(parseDialog, "VisualStudio12_32.prf");
		
		pressButtonByText(parseDialog, "Parse to Program", false);
		
		pressButtonByText(waitForDialogComponent("Confirm"), "Continue", false);
		
		pressButtonByText(waitForDialogComponent("Use Open Archives?"), "Don't Use Open Archives", false);
	}
	
	// switch between two
	//    change, test ask save if change
	@Test
	public void testSetLanguage() throws Exception {
		initTool(program);

		ParseDialog parseDialog = showParseDialog();

		//
		// test switch to new profile after changes, NO to save changes
		
		this.setSelectedParseProfile(parseDialog, "VisualStudio12_32.prf");
		
		setLanguage(parseDialog, "8051:BE:16:default", "default");
		
		runSwing(() -> {
			this.setSelectedParseProfile(parseDialog, "VisualStudio12_64.prf");
		}, false);
		
		pressButtonByText(waitForDialogComponent("Save Changes to Another Profile?"), "No", false);
		
		
		assertEquals("VisualStudio12_64.prf",parseDialog.getCurrentItem().getName());
		
		//
		// test forced save as new profile, doesn't exist
		setLanguage(parseDialog, "8051:BE:16:default", "default");
		
		runSwing(() -> {
			this.setSelectedParseProfile(parseDialog, "VisualStudio12_32.prf");
		}, false);
		
		// make sure profile is gone
		ResourceFile userProfileParent = parseDialog.getUserProfileParent();
		File f = new File(userProfileParent.getAbsolutePath(),"MyTestProfile.prf");
		f.delete();
		
		pressButtonByText(waitForDialogComponent("Save Changes to Another Profile?"), "Yes", false);
		
		InputDialog dialog = waitForDialogComponent(InputDialog.class);

		dialog.setValue("MyTestProfile");
		pressButtonByText(dialog, "OK");
		waitForSwing();
		
		assertEquals("MyTestProfile.prf",parseDialog.getCurrentItem().getName());
		
		// test save as forced to an existing profile
	
		runSwing(() -> {
			this.setSelectedParseProfile(parseDialog, "VisualStudio12_64.prf");
		}, false);
		
		setLanguage(parseDialog, "x86:LE:64:default", "gcc");
		
		runSwing(() -> {
			this.setSelectedParseProfile(parseDialog, "VisualStudio12_32.prf");
		}, false);
		
		pressButtonByText(waitForDialogComponent("Save Changes to Another Profile?"), "Yes", false);
		
		dialog = waitForDialogComponent(InputDialog.class);

		dialog.setValue("MyTestProfile");
		pressButtonByText(dialog, "OK");
		waitForSwing();
		
		pressButtonByText(waitForDialogComponent("Overwrite Existing File?"), "Yes", false);
		
		waitForSwing();
		
		assertEquals("MyTestProfile.prf",parseDialog.getCurrentItem().getName());

		// test save the current USER profile when switching
	
		runSwing(() -> {
			this.setSelectedParseProfile(parseDialog, "MyTestProfile.prf");
		}, false);
		
		setLanguage(parseDialog, "8051:BE:16:default", "default");
		
		runSwing(() -> {
			this.setSelectedParseProfile(parseDialog, "VisualStudio12_32.prf");
		}, false);
		
		pressButtonByText(waitForDialogComponent("Save Changes to Profile?"), "Yes", false);
		
		assertEquals("VisualStudio12_32.prf",parseDialog.getCurrentItem().getName());
		
	}

	private void setLanguage(ParseDialog parseDialog, String langID, String compID) {
		runSwing(() -> {
			pressButton(parseDialog.getLanguageButton());
		}, false);
		
		SetLanguageDialog dlg = waitForDialogComponent(SetLanguageDialog.class);
		assertNotNull(dlg);
		NewLanguagePanel languagePanel =
			(NewLanguagePanel) getInstanceField("selectLangPanel", dlg);
		assertNotNull(languagePanel);

		waitForSwing();

		runSwing(() -> {
			NewLanguagePanel selectLangPanel =
				(NewLanguagePanel) getInstanceField("selectLangPanel", dlg);
			selectLangPanel.setSelectedLcsPair(
				new LanguageCompilerSpecPair(new LanguageID(langID), new CompilerSpecID(compID)));
		}, true);

		waitForSwing();

		pressButtonByText(dlg, "OK");
	}
	
	// test parse to file, choose file
	@Test
	public void testImportToFile() throws Exception {

		initTool(program);

		ParseDialog parseDialog = showParseDialog();
		
		this.setSelectedParseProfile(parseDialog, "VisualStudio12_32.prf");
		
		setLanguage(parseDialog, "8051:BE:16:default", "default");
		
		final File tmpDir = createTempDirectory("GDT");
		FileUtilities.checkedMkdir(tmpDir);
		
		// open an archive
		// write out a dummy header file to read
		File dummyHeader = this.createTempFile("dummy.h");
		
		FileUtilities.deleteDir(dummyHeader);
		
		String files[] = {dummyHeader.getName()};
		
		this.setFiles(parseDialog, files);
		
		String includePath[] = {dummyHeader.getParent()};
		
		this.setIncludePaths(parseDialog, includePath);
		
		pressButtonByText(parseDialog, "Parse to File...", false);
		
		final GhidraFileChooser fileChooser = waitForDialogComponent(GhidraFileChooser.class);
		
		runSwing(() -> fileChooser.setSelectedFile(new File(tmpDir, "dummy")));
		
		waitForUpdateOnChooser(fileChooser);

		pressButtonByName(fileChooser.getComponent(), "OK");
		
		// dummy file empty, error
		pressButtonByText(waitForDialogComponent("Parse Errors"), "OK", false);

		// dummy file full, OK
		FileUtilities.writeStringToFile(dummyHeader,
	        "typedef int wchar_t;\n" +
	        "struct mystruct {\n" +
	        "    wchar_t defined_wchar_t;\n" +
	        "};\n");
		
		this.setFiles(parseDialog, files);

		pressButtonByText(parseDialog, "Parse to File...", false);
		
		final GhidraFileChooser existsChooser = waitForDialogComponent(GhidraFileChooser.class);
		
		final File GDTarchiveFile = new File(tmpDir, "dummy.gdt");
		
		runSwing(() -> existsChooser.setSelectedFile(GDTarchiveFile), true);
		
		waitForUpdateOnChooser(existsChooser);

		pressButtonByName(existsChooser.getComponent(), "OK");

		pressButtonByText(waitForDialogComponent("Overwrite Existing File?"), "Yes", false);

		pressButtonByText(waitForDialogComponent("C-Parse of Header Files Complete"), "OK", false);
		
		waitForBusyTool(tool);

		// open the file archive		
		FileDataTypeManager fileArchive = FileDataTypeManager.openFileArchive(GDTarchiveFile, false);
		try {
			DataType dataType =
				fileArchive.getDataType("/" + dummyHeader.getName() + "/" + "mystruct");
			assertNotNull("mystruct parsed into program", dataType);
		}
		finally {
			fileArchive.close();
		}
	}

	// test parse to file, choose file
	@Test
	public void testImportToFileUseArchive() throws Exception {

		initTool(program);

		ParseDialog parseDialog = showParseDialog();
		
		// open an archive
		dtmPlugin.openDataTypeArchive("windows_vs12_64");
		
		this.setSelectedParseProfile(parseDialog, "VisualStudio12_32.prf");
		
		setLanguage(parseDialog, "8051:BE:16:default", "default");
		
		final File tmpDir = createTempDirectory("GDT");
		FileUtilities.checkedMkdir(tmpDir);
		
		// open an archive
		// write out a dummy header file to read
		File dummyHeader = this.createTempFile("dummy.h");
		
		FileUtilities.deleteDir(dummyHeader);
		
		String files[] = {dummyHeader.getName()};
		
		String includePath[] = {dummyHeader.getParent()};
		
		this.setIncludePaths(parseDialog, includePath);

		// dummy file full, OK
		FileUtilities.writeStringToFile(dummyHeader,
	        "typedef int wchar_t;\n" +
	        "struct mystruct {\n" +
	        "    wchar_t defined_wchar_t;\n" +
	        "    wint_t defined_from_windows;\n" +
	        "};\n");
		
		this.setFiles(parseDialog, files);

		pressButtonByText(parseDialog, "Parse to File...", false);
		
		final GhidraFileChooser existsChooser = waitForDialogComponent(GhidraFileChooser.class);
		
		final File GDTarchiveFile = new File(tmpDir, "dummy.gdt");
		
		runSwing(() -> existsChooser.setSelectedFile(GDTarchiveFile), true);
		
		waitForUpdateOnChooser(existsChooser);

		pressButtonByName(existsChooser.getComponent(), "OK");

		pressButtonByText(waitForDialogComponent("Use Open Archives?"), "Use Open Archives", false);	
		
		waitForBusyTool(tool);

		pressButtonByText(waitForDialogComponent("C-Parse of Header Files Complete"), "OK", false);
		
		// open the file archive		
		FileDataTypeManager fileArchive = FileDataTypeManager.openFileArchive(GDTarchiveFile, false);
		try {
			DataType dataType =
				fileArchive.getDataType("/" + dummyHeader.getName() + "/" + "mystruct");

			assertNotNull("mystruct parsed into program", dataType);

			Structure struct = (Structure) dataType;

			DataTypeComponent component = struct.getComponent(1);
			assertEquals(component.getDataType().getName(), "wint_t");
		}
		finally {
			fileArchive.close();
		}
	}

	
	private void startSetLanguage(LanguageID languageID, CompilerSpecID compilerSpecID) throws Exception {
		if (languageID == null) {
			throw new RuntimeException("languageID == null not allowed");
		}
		if (compilerSpecID == null) {
			throw new RuntimeException("compilerSpecID == null not allowed");
		}

		SetLanguageDialog dlg = waitForDialogComponent(SetLanguageDialog.class);
		assertNotNull(dlg);
		NewLanguagePanel languagePanel =
			(NewLanguagePanel) getInstanceField("selectLangPanel", dlg);
		assertNotNull(languagePanel);

		waitForSwing();

		runSwing(() -> {
			NewLanguagePanel selectLangPanel =
				(NewLanguagePanel) getInstanceField("selectLangPanel", dlg);
			selectLangPanel.setSelectedLcsPair(
				new LanguageCompilerSpecPair(languageID, compilerSpecID));
		}, true);

		waitForSwing();

		pressButtonByText(dlg, "OK");
	}

	private void assertResultDialog() {
		Window aboutDialog = waitForWindow(TITLE);
		assertNotNull(aboutDialog);
		pressButtonByText(aboutDialog, "OK");
	}

	private ParseDialog showParseDialog() {

		//ActionContext actionContext = cbPlugin.getProvider().getActionContext(null);
		performAction(cparserAction, false);
		ParseDialog parseDialog = waitForDialogComponent(ParseDialog.class);
		assertNotNull(parseDialog);
		return parseDialog;
	}

	private void setOption(ParseDialog dialog, String options) {
		runSwing(() -> {
			JTextArea parseOptionsTextField = dialog.getParseOptionsTextField();
			parseOptionsTextField.setText(options);
		});
	}
	
	private void setIncludePaths(ParseDialog dialog, String paths[]) {
		runSwing(() -> {
			PathnameTablePanel incPaths = dialog.getIncludePaths();
			incPaths.setPaths(paths);
		});
	}
	
	private void setFiles(ParseDialog dialog, String files[]) {
		runSwing(() -> {
			PathnameTablePanel sourceFiles = dialog.getSourceFiles();
			sourceFiles.setPaths(files);
		});
	}

	private void setSelectedParseProfile(ParseDialog dialog, String profileName) {
		runSwing(() -> {
			GhidraComboBox<ParseDialog.ComboBoxItem> parseComboBox = dialog.getParseComboBox();
			ArrayList<ComboBoxItem> profiles = dialog.getProfiles();
			int index = 0;
			for (ComboBoxItem comboBoxItem : profiles) {
				if (profileName.equals(comboBoxItem.getName())) {
					parseComboBox.setSelectedIndex(index);
					break;
				}
				index++;
			}
		});
	}

}
