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
package ghidra.app.plugin.core.diff;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.util.Date;
import java.util.Set;

import javax.swing.*;

import org.junit.*;

import docking.*;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.tool.ToolConstants;
import docking.widgets.fieldpanel.FieldPanel;
import generic.test.AbstractGenericTest;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.main.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.InvalidNameException;
import ghidra.util.SaveableColor;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DiffTestAdapter extends AbstractGhidraHeadedIntegrationTest {
	protected ProgramDiff programDiff;
	protected ProgramBuilder programBuilderDiffTest1;
	protected ProgramBuilder programBuilderDiffTest2;
	protected Program diffTestP1;
	protected Program diffTestP2;

	protected TestEnv env;
	protected PluginTool tool;
	protected FrontEndTool frontEndTool;
	protected AddressFactory addrFactory;
	protected AddressSpace space;
	protected Program program;
	protected FrontEndPlugin frontEndPlugin;
	protected CodeBrowserPlugin cb;
	protected ProgramDiffPlugin diffPlugin;
	protected FieldPanel fp1;
	protected FieldPanel fp2;
	protected ListingPanel diffListingPanel;
	protected ToggleDockingAction openClosePgm2;
	protected DockingActionIf viewGroupChanges;
	protected DockingActionIf viewDiffs;
	protected DockingActionIf applyDiffs;
	protected DockingActionIf applyDiffsNext;
	protected DockingActionIf ignoreDiffs;
	protected DockingActionIf nextDiff;
	protected DockingActionIf prevDiff;
	protected DockingActionIf diffDetails;
	protected DockingActionIf diffApplySettings;
	protected DockingActionIf getDiffs;
	protected DockingActionIf selectAllDiffs;
	protected DockingActionIf setPgm2Selection;

	ExecuteDiffDialog getDiffsDialog;
	JCheckBox programContextCB;
	JCheckBox byteCB;
	JCheckBox codeUnitCB;
	JCheckBox refCB;
	JCheckBox commentCB;
	JCheckBox labelCB;
	JCheckBox functionCB;
	JCheckBox bookmarkCB;
	JCheckBox propertiesCB;

	JCheckBox limitToSelectionCB;
	JTextArea limitText;

	int txId;

	ProgramTreePlugin pt;
	ComponentProvider programTreeProvider;
	DockingActionIf replaceView;
	DockingActionIf goToView;
	DockingActionIf removeView;

	private ProgramBuilder buildDiffTestPgm1() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("DiffTestPgm1", ProgramBuilder._X86);
		Namespace globalNamespace = builder.getProgram().getGlobalNamespace();
		String globalNamespaceName = globalNamespace.getName();

		builder.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		builder.createMemory("d2", "0x200", 0x100);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".datau", "0x1008600", 0x1344);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);

		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent

		// bytes
		builder.setBytes("0x1002b45", new byte[] { (byte) 0xee });
		builder.setBytes("0x1002b49", new byte[] { (byte) 0x57 });

		// code units
		builder.setBytes("0x1002261", "6a 01", true);
		builder.setBytes("0x010024b8", "8b", false);
		builder.setBytes("0x010024b9", "45 10 83 e8 00 74 16", true);

		// program context
		String AL_REGISTER = "AL";
		String AX_REGISTER = "AX";
		String EAX_REGISTER = "EAX";
		String DR0_REGISTER = "DR0";
		String SS_REGISTER = "SS";
		String CF_REGISTER = "CF";
		builder.setRegisterValue(DR0_REGISTER, "0x10022d4", "0x10022e5", 0x1010101);
		builder.setRegisterValue(DR0_REGISTER, "0x1002329", "0x100232f", 0x40e20100);
		builder.setRegisterValue(AX_REGISTER, "0x1002378", "0x100238f", 0xdc52);
//		builder.setRegisterValue(AL_REGISTER, "0x1002378", "0x100238f", 0x52);
//		builder.setRegisterValue(AH_REGISTER, "0x1002378", "0x100238f", 0xdc);
		builder.setRegisterValue(DR0_REGISTER, "0x1003bfc", "0x1003c10", 0x91ef0600);
		builder.setRegisterValue(DR0_REGISTER, "0x1003c1c", "0x1003c36", 0x71f25b2e);
		builder.setRegisterValue(EAX_REGISTER, "0x1003c52", "0x1003c57", 0x1caf7d1a);
		builder.setRegisterValue(SS_REGISTER, "0x1003cd0", "0x1003cdc", 0x3582);
		builder.setRegisterValue(CF_REGISTER, "0x1005e4f", "0x1005e53", 0x0);
		builder.setRegisterValue(AL_REGISTER, "0x1005e51", "0x1005e53", 0x5);

		// references
		builder.createMemoryReference("0x01002a2a", "0x01002a25", RefType.DATA,
			SourceType.USER_DEFINED);
		builder.createExternalReference("0x01001034", "yourLib.dll", "GetStuff", "0x77f42caa", 0);

		// comments
		builder.createComment("1002040", "Plate in P1.", CodeUnit.PLATE_COMMENT);
		builder.createComment("1002040", "Pre in P1.", CodeUnit.PRE_COMMENT);
		builder.createComment("1002040", "EOL in P1.", CodeUnit.EOL_COMMENT);
		builder.createComment("1002040", "Repeatable in P1.", CodeUnit.REPEATABLE_COMMENT);
		builder.createComment("1002040", "Post in P1.", CodeUnit.POST_COMMENT);

		builder.createComment("1002304", "EOL comment", CodeUnit.EOL_COMMENT);
		builder.createComment("1002306", "\"Pre Comment\"", CodeUnit.PRE_COMMENT);
		builder.createComment("100230b", "Plate Comment", CodeUnit.PRE_COMMENT);
		builder.createComment("100230b", "Post Comment", CodeUnit.PRE_COMMENT);
		builder.createComment("100230d", "simple comment", CodeUnit.PRE_COMMENT);
		builder.createComment("100230d", "simple comment", CodeUnit.EOL_COMMENT);
		builder.createComment("100230d", "simple comment", CodeUnit.POST_COMMENT);
		builder.createComment("100230d", "simple comment", CodeUnit.REPEATABLE_COMMENT);
		builder.createComment("100230d", "simple comment", CodeUnit.PLATE_COMMENT);

		builder.createComment("1002312", "\"My comment that the other comment is in.\"",
			CodeUnit.PRE_COMMENT);
		builder.createComment("1002312", "My comment that the other comment is in.",
			CodeUnit.EOL_COMMENT);
		builder.createComment("1002312", "My comment that the other comment is in.",
			CodeUnit.POST_COMMENT);
		builder.createComment("1002312", "My comment that the other comment is in.",
			CodeUnit.PLATE_COMMENT);

		builder.createComment("1002336", "ONE: Repeatable comment.", CodeUnit.REPEATABLE_COMMENT);

		builder.createComment("1002346", "Easy as pie.", CodeUnit.REPEATABLE_COMMENT);

		builder.createComment("1002350", "Once upon a", CodeUnit.REPEATABLE_COMMENT);

		builder.createComment("100238f", "EOL: Program1", CodeUnit.EOL_COMMENT);

		builder.createComment("1002395", "Pre: Program1", CodeUnit.PRE_COMMENT);

//		builder.createComment("100239d", "Plate: Program1", CodeUnit.PLATE_COMMENT);
		builder.createComment("100239d", "Post: Program1", CodeUnit.POST_COMMENT);

		builder.createComment("10030d2", "FUNCTION", CodeUnit.PLATE_COMMENT);

		builder.createComment("100355f", "This is a function.", CodeUnit.PLATE_COMMENT);

		builder.createComment("100415a", "This is my function", CodeUnit.PLATE_COMMENT);

		// functions 
		DataType dt = new ByteDataType();
		Parameter p = new ParameterImpl(null, dt, builder.getProgram());
		builder.createEmptyFunction(null, "10018cf", 10, null, p);
		Function function299e = builder.createEmptyFunction(null, "100299e", 130, null, p, p, p);
		builder.createEmptyFunction(null, "1002cf5", 10, null, p, p, p, p, p);

		// labels
		builder.createLabel("1002a01", "foo", globalNamespaceName);

		builder.createLabel("1002a0d", "junk", function299e.getName());

		builder.createLabel("1002a0b", "tmp1", globalNamespaceName);

		builder.createLabel("1002a0c", "getResources", globalNamespaceName);
		builder.createLabel("1002a0c", "mySymbol", globalNamespaceName);

		// Data Types & Data
		builder.addCategory(new CategoryPath("/cat1"));

		Structure struct1 = new StructureDataType("struct_1", 0);
		struct1.add(new ByteDataType());
		struct1.add(new ByteDataType());
		struct1.add(new WordDataType());
		struct1.add(new PointerDataType());

		Structure struct2 = new StructureDataType("struct_2", 0);
		struct2.add(new ByteDataType());
		struct2.add(new WordDataType());
		struct2.add(new PointerDataType(struct2));

		Structure myStruct = new StructureDataType("MyStruct", 0);
		myStruct.add(new ByteDataType());
		myStruct.add(new CharDataType());
		myStruct.add(new WordDataType());
		myStruct.add(new PointerDataType());

		Structure myStruct1 = new StructureDataType("MyStruct1", 0);
		myStruct1.add(new ByteDataType());
		myStruct1.add(new CharDataType());
		myStruct1.add(new WordDataType());
		myStruct1.add(new PointerDataType());

		builder.applyDataType("0x01003ac8", struct1);
		builder.applyDataType("0x01003ad5", struct2);
		builder.applyDataType("0x01003ae1", struct2);
		builder.applyDataType("0x01003aed", myStruct);
		builder.applyDataType("0x01003af7", myStruct1);
		builder.applyDataType("0x01003b02", myStruct);
		builder.applyDataType("0x01003b0d", new ByteDataType());
		builder.applyDataType("0x01003b14", new FloatDataType());
		builder.applyDataType("0x01003b1c", new StringDataType());
		builder.applyDataType("0x01003b29", new PointerDataType());

		// Bookmarks
		builder.createBookmark("0x0100230b", BookmarkType.NOTE, "P1Category", "Test");
		builder.createBookmark("0x0100230c", BookmarkType.NOTE, "", "P1 has bookmark.");
		builder.createBookmark("0x01002318", BookmarkType.NOTE, "Test", "This is a test bookmark.");

		// Properties

		builder.setIntProperty("10018ae", "Space", 1);
		builder.setIntProperty("10018ba", "Space", 1);
		builder.setIntProperty("10018ff", "Space", 1);
		builder.setIntProperty("100248c", "Space", 1);

		builder.setObjectProperty("100248c", "testColor", new SaveableColor(Color.CYAN));
		builder.setObjectProperty("10039dd", "testColor", new SaveableColor(Color.BLACK));
		builder.setObjectProperty("10039f8", "testColor", new SaveableColor(Color.BLACK));
		builder.setObjectProperty("10039fe", "testColor", new SaveableColor(Color.RED));

		AbstractGenericTest.setInstanceField("recordChanges", builder.getProgram(), Boolean.TRUE);

		return builder;
	}

	private ProgramBuilder buildDiffTestPgm2() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("DiffTestPgm2", ProgramBuilder._X86);
		Namespace globalNamespace = builder.getProgram().getGlobalNamespace();
		String globalNamespaceName = globalNamespace.getName();

		builder.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		builder.createMemory("d4", "0x400", 0x100);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".datau", "0x1008600", 0x1344);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);

		builder.setProperty(Program.DATE_CREATED, new Date(100000000)); // arbitrary, but consistent

		// bytes
		builder.setBytes("0x1002b45", new byte[] { (byte) 0x8b });
		builder.setBytes("0x1002b49", new byte[] { (byte) 0xee });

		// code units
		builder.setBytes("0x1002261", "6a 01", true);
		builder.createEquate("0x01002261", "uno", 0x1, 0);
		builder.setBytes("0x010024b8", "8b 45 10 83 e8 00", true);
		builder.setBytes("0x010024be", "74 16", false);

		// program context
		String AL_REGISTER = "AL";
		String AX_REGISTER = "AX";
		String EAX_REGISTER = "EAX";
		String DR0_REGISTER = "DR0";
		String SS_REGISTER = "SS";
		String CF_REGISTER = "CF";
		builder.setRegisterValue(AL_REGISTER, "0x10022ee", "0x10022fc", 0xfe);
		builder.setRegisterValue(DR0_REGISTER, "0x100233c", "0x1002345", 0x40e20100);
		builder.setRegisterValue(AX_REGISTER, "0x100238a", "0x1002396", 0x672b);
//		builder.setRegisterValue(AL_REGISTER, "0x100238a", "0x1002396", 0x2b);
//		builder.setRegisterValue(AH_REGISTER, "0x100238a", "0x1002396", 0x67);
		builder.setRegisterValue(DR0_REGISTER, "0x1003c02", "0x1003c07", 0x91ef0600);
		builder.setRegisterValue(DR0_REGISTER, "0x1003c23", "0x1003c2a", 0xffc99a3b);
		builder.setRegisterValue(EAX_REGISTER, "0x1003c40", "0x1003c61", 0x1caf7d1a);
		builder.setRegisterValue(SS_REGISTER, "0x1003c9c", "0x1003cf2", 0x3d9);
		builder.setRegisterValue(CF_REGISTER, "0x1005e4f", "0x1005e53", 0x1);

		// references
		builder.createMemoryReference("0x01002a2a", "0x01002a23", RefType.DATA,
			SourceType.USER_DEFINED);
		builder.createExternalReference("0x01001034", "myLib.dll", "GetStuff", "0x77f42caa", 0);

		// comments
		builder.createComment("100204c", "My multi-line plate\ncomment for program2.",
			CodeUnit.PLATE_COMMENT);
		builder.createComment("100204c", "My multi-line pre\ncomment for program2.",
			CodeUnit.PRE_COMMENT);
		builder.createComment("100204c", "My multi-line EOL\ncomment for program2.",
			CodeUnit.EOL_COMMENT);
		builder.createComment("100204c", "My multi-line repeatable\ncomment for program2.",
			CodeUnit.REPEATABLE_COMMENT);
		builder.createComment("100204c", "My multi-line post\ncomment for program2.",
			CodeUnit.POST_COMMENT);

		builder.createComment("100230d", "This is a simple comment for example.",
			CodeUnit.PRE_COMMENT);
		builder.createComment("100230d", "This is a simple comment for example.",
			CodeUnit.EOL_COMMENT);
		builder.createComment("100230d", "This is a simple comment for example.",
			CodeUnit.POST_COMMENT);
		builder.createComment("100230d", "This is a simple comment for example.",
			CodeUnit.REPEATABLE_COMMENT);
		builder.createComment("100230d", "This is a simple comment for example.",
			CodeUnit.PLATE_COMMENT);

		builder.createComment("1002312", "My comment", CodeUnit.PRE_COMMENT);
		builder.createComment("1002312", "My comment", CodeUnit.EOL_COMMENT);
		builder.createComment("1002312", "My comment", CodeUnit.POST_COMMENT);
		builder.createComment("1002312", "My comment", CodeUnit.PLATE_COMMENT);

		builder.createComment("1002329", "Before the code unit", CodeUnit.PRE_COMMENT);
		builder.createComment("1002329", "End of the line.", CodeUnit.EOL_COMMENT);
		builder.createComment("1002329", "After the code unit", CodeUnit.POST_COMMENT);
		builder.createComment("1002329", "PLATE", CodeUnit.PLATE_COMMENT);

		builder.createComment("1002336", "TWO: Repeatable comment.", CodeUnit.REPEATABLE_COMMENT);

		builder.createComment("1002346", "Easy", CodeUnit.REPEATABLE_COMMENT);

		builder.createComment("1002350", "Once upon a time...", CodeUnit.REPEATABLE_COMMENT);

		builder.createComment("100238f", "EOL: Program2", CodeUnit.EOL_COMMENT);

		builder.createComment("1002395", "Pre: Program2", CodeUnit.PRE_COMMENT);

//		builder.createComment("100239d", "Plate: Program2", CodeUnit.PLATE_COMMENT);
		builder.createComment("100239d", "Post: Program2", CodeUnit.POST_COMMENT);

		builder.createComment("1002a91", "FUNCTION", CodeUnit.PLATE_COMMENT);

		builder.createComment("100415a", "This is my function for testing diff",
			CodeUnit.PLATE_COMMENT);

		// functions 
		DataType dt = new ByteDataType();
		Parameter p = new ParameterImpl(null, dt, builder.getProgram());
		builder.createEmptyFunction(null, "100299e", 130, null, p, p);
		builder.createStackReference("0x010029d1", RefType.READ, 0x10, SourceType.USER_DEFINED, 0);

		// labels
		builder.createLabel("1002a03", "foo", globalNamespaceName);
		builder.createLabel("1002a0b", "tmp1", globalNamespaceName);
		builder.createLabel("1002a0b", "tmp2", globalNamespaceName);
		builder.createLabel("1002a0b", "stuff", globalNamespaceName);

		builder.createLabel("1002a0c", "begin", globalNamespaceName);
		builder.createLabel("1002a0c", "fooBar234", globalNamespaceName);
		builder.createLabel("1002a0c", "sub21001", globalNamespaceName);

		builder.createLabel("1002a0d", "junk", globalNamespaceName);

		// Data Types & Data

		Structure struct1 = new StructureDataType("struct_1", 0);
		struct1.add(new ByteDataType());
		struct1.add(new CharDataType());
		struct1.add(new WordDataType());
		struct1.add(new PointerDataType());

		Union union1 = new UnionDataType("union_1");
		union1.add(new ByteDataType());
		union1.add(new WordDataType());
		union1.add(new DWordDataType());

		Structure struct2 = new StructureDataType("struct_2", 0);
		struct2.add(new ByteDataType());
		struct2.add(new WordDataType());
		struct2.add(new PointerDataType(union1));

		Structure myStruct = new StructureDataType("MyStruct", 0);
		myStruct.add(new ByteDataType());
		myStruct.add(new CharDataType());
		myStruct.add(new WordDataType());
		myStruct.add(new PointerDataType());

		Structure struct3 = new StructureDataType("struct_3", 0);
		struct3.add(new ByteDataType());
		struct3.add(new FloatDataType());

		builder.applyDataType("0x01003ac8", struct1);
		builder.applyDataType("0x01003ad5", struct2);
		builder.applyDataType("0x01003ae1", union1);
		builder.applyDataType("0x01003aec", myStruct);
		builder.applyDataType("0x01003af7", myStruct);
		builder.applyDataType("0x01003b02", myStruct);
		builder.applyDataType("0x01003b0d", new DWordDataType());
		builder.applyDataType("0x01003b14", new DWordDataType());
		builder.applyDataType("0x01003b1c", new UnicodeDataType());
		builder.applyDataType("0x01003b29", new PointerDataType(new DWordDataType()));

		// Bookmarks
		builder.createBookmark("0x0100230b", BookmarkType.NOTE, "P2Category", "Test");
		builder.createBookmark("0x0100230d", BookmarkType.NOTE, "", "P2 has bookmark.");
		builder.createBookmark("0x01002318", BookmarkType.NOTE, "Test",
			"This is a different test bookmark.");

		// Properties

		builder.setIntProperty("10018ba", "Space", 1);
		builder.setIntProperty("10018ce", "Space", 2);
		builder.setIntProperty("10018ff", "Space", 2);
		builder.setIntProperty("1002428", "Space", 1);
		builder.setIntProperty("100248c", "Space", 1);

		builder.setObjectProperty("100248c", "testColor", new SaveableColor(Color.WHITE));
		builder.setObjectProperty("10039f1", "testColor", new SaveableColor(Color.BLACK));
		builder.setObjectProperty("10039f8", "testColor", new SaveableColor(Color.BLACK));
		builder.setObjectProperty("10039fe", "testColor", new SaveableColor(Color.GREEN));

		AbstractGenericTest.setInstanceField("recordChanges", builder.getProgram(), Boolean.TRUE);

		return builder;
	}

	@Before
	public void setUp() throws Exception {

		programBuilderDiffTest1 = buildDiffTestPgm1();
		programBuilderDiffTest2 = buildDiffTestPgm2();
		diffTestP1 = programBuilderDiffTest1.getProgram();
		diffTestP2 = programBuilderDiffTest2.getProgram();

		fixupGUI();
		env = new TestEnv();
		tool = env.showTool();
		frontEndTool = env.showFrontEndTool();
		frontEndPlugin = getPlugin(frontEndTool, FrontEndPlugin.class);
		setUpCodeBrowserTool(tool);

		diffListingPanel = diffPlugin.getListingPanel();
		fp1 = cb.getFieldPanel();
		fp2 = diffListingPanel.getFieldPanel();
		openClosePgm2 = (ToggleDockingAction) getAction(diffPlugin, "Open/Close Program View");

		tool.addPlugin(ProgramTreePlugin.class.getName());
		pt = env.getPlugin(ProgramTreePlugin.class);
		showProgramTree();
		replaceView = getAction(pt, "Replace View");
		goToView = getAction(pt, "Go To start of folder/fragment in View");
		removeView = getAction(pt, "Remove folder/fragment from View");

	}

	protected void setUpCodeBrowserTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(ProgramDiffPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(MarkerManagerPlugin.class.getName());
		cb = getPlugin(tool, CodeBrowserPlugin.class);
		diffPlugin = getPlugin(tool, ProgramDiffPlugin.class);
	}

	@After
	public void tearDown() {

		Window win = getWindow("Select Other Program");
		if (win != null) {
			pressButton(win, "Cancel");
		}

		env.dispose();
	}

	void closeDiff() throws Exception {

		closeDiffByAction();
		DialogComponentProvider dialogProvider = waitForDialogComponent("Close Diff Session");
		assertNotNull("Did not get confirmation dialog", dialogProvider);
		pressButtonByText(dialogProvider.getComponent(), "Yes", true);
		waitForSwing();
	}

	void save() {
		ProgramManagerPlugin pm = env.getPlugin(ProgramManagerPlugin.class);
		Program p1 = pm.getCurrentProgram();
		DockingActionIf saveAction = getAction(pm, "Save File");
		invokeLater(saveAction);

		waitForCondition(() -> !p1.isLocked());
	}

	Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	void setLocation(String address) {
		tool.firePluginEvent(new ProgramLocationPluginEvent("test",
			new ProgramLocation(program, addr(address)), program));
		assertEquals(addr(address), getDiffAddress());
	}

	void checkForHorizontalAlignment() {
		Rectangle bounds1 = fp1.getParent().getParent().getParent().getParent().getBounds();
		Rectangle bounds2 = fp2.getParent().getParent().getParent().getBounds();
		assertTrue(bounds1.x + bounds1.width == bounds2.x);
		assertTrue(bounds1.y == bounds2.y);
	}

	void checkForVerticalAlignment() {
		Rectangle bounds1 = fp1.getParent().getParent().getParent().getParent().getBounds();
		Rectangle bounds2 = fp2.getParent().getParent().getParent().getBounds();
		assertTrue(bounds1.x == bounds2.x);
		assertTrue(bounds1.y + bounds1.height == bounds2.y);
	}

	void loadProgram(final String programName) {
		program = env.getProgram(programName);
		openProgram(program);
		addrFactory = program.getAddressFactory();
		space = addrFactory.getDefaultAddressSpace();
	}

	void loadProgram(final Program p) {
		openProgram(p);
	}

	void openProgram(final Program p) {
		program = p;
		addrFactory = program.getAddressFactory();
		space = addrFactory.getDefaultAddressSpace();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(p);
	}

	Program openProgram(final String programName) {

		ProgramDB p = env.getProgram(programName);
		openProgram(p);
		waitForSwing();

		Program pgm = p;
		addrFactory = pgm.getAddressFactory();
		space = addrFactory.getDefaultAddressSpace();
		return pgm;
	}

	void closeProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm.getCurrentProgram() != null) {
			pm.closeProgram();
		}
	}

	public static DockingActionIf getToolAction(PluginTool tool, String name) {
		Set<DockingActionIf> actions = getActionsByOwner(tool, ToolConstants.TOOL_OWNER);
		for (DockingActionIf action : actions) {
			if (name.equals(action.getName())) {
				return action;
			}
		}
		return null;
	}

	void openSecondProgram(String pgm1, String pgm2) throws Exception {

		showTool(frontEndTool);

		env.showTool();

		loadProgram(pgm1);

		pickSecondProgram(pgm2); // 200 ms

		waitForTasks();

		Window win = waitForWindow("Determine Program Differences");
		assertNotNull(win);
		pressButton(win, "Cancel");
		getDiffActions();
	}

	void openSecondProgram(Program pgm1, Program pgm2) throws Exception {

		showTool(frontEndTool);

		env.showTool();

		loadProgram(pgm1);

		pickSecondProgram(pgm2); // 200 ms

		waitForTasks();

		Window win = waitForWindow("Determine Program Differences");
		assertNotNull(win);
		pressButton(win, "Cancel");
		getDiffActions();
	}

	void openDiff(String pgm1, String pgm2) {
		loadProgram(pgm1);
		openDiff(pgm2);
	}

	void openDiff(Program pgm1, Program pgm2) {
		program = pgm1;
		loadProgram(pgm1);
		openDiff(pgm2);
	}

	void openDiff_CloseWarningDialog(Program pgm1, Program pgm2) {
		program = pgm1;
		loadProgram(pgm1);
		openDiff(pgm2);

		Window dialog = waitForWindow("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForSwing();
	}

	void pickSecondProgram(String pgm2) {
		Program program2 = env.getProgram(pgm2);
		pickSecondProgram(program2);
	}

	void pickSecondProgram(final Program program2) {

		program2.addConsumer(diffPlugin);

		OpenVersionedFileDialogTestFake dialog = new OpenVersionedFileDialogTestFake(program2);
		diffPlugin.setOpenDiffProgramDialog(dialog);

		launchDiffByAction();

		dialog.notifyProgramChosen();
	}

	void openDiff(String pgm2) {
		Program program2 = env.getProgram(pgm2);
		openDiff(program2);
	}

	void openDiff(Program program2) {
		pickSecondProgram(program2);

		Window win = waitForWindow("Determine Program Differences");
		assertNotNull(win);
		pressButton(win, "OK");
		assertTrue(!win.isShowing());

		// wait for "Checking Program Differences"
		waitForTasks();

		getDiffActions();
	}

	void pressButton(Container container, String buttonText) {
		JButton button = findButtonByText(container, buttonText);
		assertNotNull(button);
		Runnable r = () -> button.doClick();
		SwingUtilities.invokeLater(r);
		waitForSwing();
	}

	void getDiffActions() {
		viewDiffs = getAction(diffPlugin, "View Program Differences");
		applyDiffs = getAction(diffPlugin, "Apply Differences");
		applyDiffsNext = getAction(diffPlugin, "Apply Differences and Goto Next Difference");
		ignoreDiffs = getAction(diffPlugin, "Ignore Selection and Goto Next Difference");
		nextDiff = getAction(diffPlugin, "Next Difference");
		prevDiff = getAction(diffPlugin, "Previous Difference");
		diffDetails = getAction(diffPlugin, "Diff Location Details");
		diffApplySettings = getAction(diffPlugin, "Show Diff Apply Settings");
		getDiffs = getAction(diffPlugin, "Get Differences");
		selectAllDiffs = getAction(diffPlugin, "Select All Differences");
		setPgm2Selection = getAction(diffPlugin, "Set Program1 Selection On Program2");
	}

	void invokeLater(DockingActionIf action) {
		performAction(action, false);
		waitForSwing();
	}

	void launchDiffByAction() {
		setToggleActionSelected(openClosePgm2, new ActionContext(), true, false);
	}

	void closeDiffByAction() {
		setToggleActionSelected(openClosePgm2, new ActionContext(), false, false);
	}

	void invokeAndWait(DockingActionIf action) {
		performAction(action);
	}

	<T extends Component> T getComponentOfType(Container container, Class<T> componentClass) {
		Component[] comps = container.getComponents();
		for (Component element : comps) {
			if (componentClass.isInstance(element)) {
				return componentClass.cast(element);
			}
			else if (element instanceof Container) {
				T subComp = getComponentOfType((Container) element, componentClass);
				if (subComp != null) {
					return subComp;
				}
			}
		}
		return null;
	}

	Address getDiffAddress() {
		DiffController dc = diffPlugin.getDiffController();
		if (dc != null) {
			return dc.getCurrentAddress();
		}
		return diffPlugin.getCurrentAddress();
	}

	void setCheckBoxes(final boolean select, final JCheckBox[] cbs) {

		runSwing(() -> {
			for (JCheckBox element : cbs) {

				if (element.isSelected() == select) {
					continue;
				}

				element.doClick(0);
			}
		}, false);
		waitForSwing();
	}

	void waitForDiff() throws Exception {

		waitForTasks();

		// Wait until the Diff task window goes away.
		waitForCondition(() -> !diffPlugin.isTaskInProgress());
	}

	String getDisplayableAddressSet(ProgramSelection selection) {
		StringBuffer buf = new StringBuffer();
		for (AddressRange range : selection) {
			buf.append("[" + range.getMinAddress().toString() + ", " +
				range.getMaxAddress().toString() + "]");
			buf.append("\n");
		}
		return buf.toString();
	}

	ProgramSelection getPgmByteDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("100"), addr("1ff"));
		as.addRange(addr("1002b45"), addr("1002b45"));
		as.addRange(addr("1002b49"), addr("1002b49"));
		// Now add the memory only in program1.
		as.addRange(addr("00000200"), addr("000002ff"));
		// Now add the memory only in program2.
		as.addRange(addr("00000400"), addr("000004ff"));
		as = getCodeUnitSet(as, diffPlugin.getSecondProgram());
		return new ProgramSelection(getCodeUnitSet(as, program));
	}

	ProgramSelection getPgmCodeUnitDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("1002261"), addr("1002262"));
		as.addRange(addr("10024b8"), addr("10024bf"));
		as.addRange(addr("1003ac8"), addr("1003acf"));
		as.addRange(addr("1003ad5"), addr("1003adb"));
		as.addRange(addr("1003ae1"), addr("1003ae7"));
		as.addRange(addr("1003aec"), addr("1003af4"));
		as.addRange(addr("1003af7"), addr("1003afe"));
		as.addRange(addr("1003b0d"), addr("1003b10"));
		as.addRange(addr("1003b14"), addr("1003b17"));
		as.addRange(addr("1003b1c"), addr("1003b1d"));
		as.addRange(addr("1003b29"), addr("1003b2c"));
		return new ProgramSelection(as);
	}

	ProgramSelection getPgmConflictDataDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("00000200"), addr("000002ff"));
		as.addRange(addr("1003ac8"), addr("1003acf"));
		as.addRange(addr("1003ad5"), addr("1003adb"));
		return new ProgramSelection(as);
	}

	ProgramSelection getPgmProgramContextDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("10022d4"), addr("10022e5"));
		as.addRange(addr("10022ee"), addr("10022fc"));
		as.addRange(addr("1002329"), addr("100232f"));
		as.addRange(addr("100233c"), addr("1002345"));
		as.addRange(addr("1002378"), addr("1002396"));
		as.addRange(addr("1003bfc"), addr("1003c01"));
		as.addRange(addr("1003c08"), addr("1003c10"));
		as.addRange(addr("1003c1c"), addr("1003c36"));
		as.addRange(addr("1003c40"), addr("1003c51"));
		as.addRange(addr("1003c58"), addr("1003c61"));
		as.addRange(addr("1003c9c"), addr("1003cf2"));
		as.addRange(addr("1005e4f"), addr("1005e53"));
		return new ProgramSelection(as);
	}

	ProgramSelection getPgmCommentDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("1002040"), addr("1002040"));
		as.addRange(addr("100204c"), addr("100204c"));
		as.addRange(addr("1002304"), addr("1002304"));
		as.addRange(addr("1002306"), addr("1002306"));
		as.addRange(addr("100230b"), addr("100230b"));
		as.addRange(addr("100230d"), addr("100230d"));
		as.addRange(addr("1002312"), addr("1002312"));
		as.addRange(addr("1002329"), addr("1002329"));
		as.addRange(addr("1002336"), addr("1002336"));
		as.addRange(addr("1002346"), addr("1002346"));
		as.addRange(addr("1002350"), addr("1002350"));
		as.addRange(addr("100238f"), addr("100238f"));
		as.addRange(addr("1002395"), addr("1002395"));
		as.addRange(addr("100239d"), addr("100239d"));
		as.addRange(addr("1002a91"), addr("1002a91"));
		as.addRange(addr("10030d2"), addr("10030d2"));
		as.addRange(addr("100355f"), addr("100355f"));
		as.addRange(addr("100415a"), addr("100415a"));
		as = getCodeUnitSet(as, diffPlugin.getSecondProgram());
		return new ProgramSelection(as);
	}

	ProgramSelection getPgmBookmarkDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("100230b"), addr("100230d"));
		as.addRange(addr("1002318"), addr("1002318"));
		as = getCodeUnitSet(as, diffPlugin.getSecondProgram());
		return new ProgramSelection(getCodeUnitSet(as, program));
	}

	ProgramSelection getSetupAllDiffsSet() {
		AddressSet as = new AddressSet();
		as.add(getSetupProgramContextDiffs());
		as.add(getSetupByteDiffs());
		as.add(getSetupCodeUnitDiffs());
		as.add(getSetupEquateDiffs());
		as.add(getSetupLabelDiffs());
		as.add(getSetupFunctionDiffs());
		as.add(getSetupReferenceDiffs());
		as.add(getSetupCommentDiffs());
		as.add(getSetupPropertyDiffs());
		as.add(getSetupBookmarkDiffs());
		return new ProgramSelection(as);
	}

	ProgramSelection getSetupProgramContextDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("10022d4"), addr("10022e5"));
		as.addRange(addr("10022ee"), addr("10022fc"));
		as.addRange(addr("1002329"), addr("100232f"));
		as.addRange(addr("100233c"), addr("1002345"));
		as.addRange(addr("1002378"), addr("1002396"));
		as.addRange(addr("1003bfc"), addr("1003c01"));
		as.addRange(addr("1003c08"), addr("1003c10"));
		as.addRange(addr("1003c1c"), addr("1003c36"));
		as.addRange(addr("1003c40"), addr("1003c51"));
		as.addRange(addr("1003c58"), addr("1003c61"));
		as.addRange(addr("1003c9c"), addr("1003cf2"));
		as.addRange(addr("1005e4f"), addr("1005e53"));
		as = getCodeUnitSet(as, diffPlugin.getSecondProgram());
		return new ProgramSelection(getCodeUnitSet(as, program));
	}

	ProgramSelection getSetupByteDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("100"), addr("1ff"));
		as.addRange(addr("1002b45"), addr("1002b45"));
		as.addRange(addr("1002b49"), addr("1002b49"));
		as = getCodeUnitSet(as, diffPlugin.getSecondProgram());
		return new ProgramSelection(getCodeUnitSet(as, program));
	}

	ProgramSelection getSetupCodeUnitDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("1002261"), addr("1002262"));
		as.addRange(addr("10024b8"), addr("10024bf"));

		as.addRange(addr("1003ac8"), addr("1003acf"));
		as.addRange(addr("1003ad5"), addr("1003adb"));
		as.addRange(addr("1003ae1"), addr("1003ae7"));
		as.addRange(addr("1003aec"), addr("1003af4"));
		as.addRange(addr("1003af7"), addr("1003afe"));
		as.addRange(addr("1003b0d"), addr("1003b10"));
		as.addRange(addr("1003b14"), addr("1003b17"));
		as.addRange(addr("1003b1c"), addr("1003b1d"));
		as.addRange(addr("1003b29"), addr("1003b2c"));
		return new ProgramSelection(as);
	}

	ProgramSelection getSetupConflictDataDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("1003ac8"), addr("1003acf")); // struct_1.conflict
		as.addRange(addr("1003ad5"), addr("1003adb")); // struct_2.conflict
		return new ProgramSelection(as);
	}

	ProgramSelection getSetupEquateDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("1002261"), addr("1002261"));
		return new ProgramSelection(as);
	}

	ProgramSelection getSetupLabelDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("10018cf"), addr("10018cf")); // p1 has function label
		as.addRange(addr("1002a01"), addr("1002a01"));
		as.addRange(addr("1002a03"), addr("1002a03"));
		as.addRange(addr("1002a0b"), addr("1002a0d"));
		as.addRange(addr("1002cf5"), addr("1002cf5"));
		as = getCodeUnitSet(as, diffPlugin.getSecondProgram());
		return new ProgramSelection(getCodeUnitSet(as, program));
	}

	ProgramSelection getSetupCommentDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("1002040"), addr("1002040"));
		as.addRange(addr("100204c"), addr("100204c"));
		as.addRange(addr("1002304"), addr("1002304"));
		as.addRange(addr("1002306"), addr("1002306"));
		as.addRange(addr("100230b"), addr("100230b"));
		as.addRange(addr("100230d"), addr("100230d"));
		as.addRange(addr("1002312"), addr("1002312"));
		as.addRange(addr("1002329"), addr("1002329"));
		as.addRange(addr("1002336"), addr("1002336"));
		as.addRange(addr("1002346"), addr("1002346"));
		as.addRange(addr("1002350"), addr("1002350"));
		as.addRange(addr("100238f"), addr("100238f"));
		as.addRange(addr("1002395"), addr("1002395"));
		as.addRange(addr("100239d"), addr("100239d"));
		as.addRange(addr("1002a91"), addr("1002a91"));
		as.addRange(addr("10030d2"), addr("10030d2"));
		as.addRange(addr("100355f"), addr("100355f"));
		as.addRange(addr("100415a"), addr("100415a"));
		as = getCodeUnitSet(as, diffPlugin.getSecondProgram());
		return new ProgramSelection(getCodeUnitSet(as, program));
	}

	ProgramSelection getSetupReferenceDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("1001034"), addr("1001034"));
		as.addRange(addr("10029d1"), addr("10029d1")); // p2 has stack ref
		as.addRange(addr("1002a2a"), addr("1002a2a")); // mem ref
		as = getCodeUnitSet(as, diffPlugin.getSecondProgram());
		return new ProgramSelection(getCodeUnitSet(as, program));
	}

	ProgramSelection getSetupFunctionDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("10018cf"), addr("10018cf")); // p1 has function
		as.addRange(addr("100299e"), addr("100299e"));
		as.addRange(addr("1002cf5"), addr("1002cf5"));
		as = getCodeUnitSet(as, diffPlugin.getSecondProgram());
		return new ProgramSelection(getCodeUnitSet(as, program));
	}

	ProgramSelection getSetupPropertyDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("10018ae"), addr("10018ae")); // p1 has space=1
		as.addRange(addr("10018ce"), addr("10018ce")); // p2 has space=2
		as.addRange(addr("10018ff"), addr("10018ff")); // p1 has space=1; p2 has space=2
		as.addRange(addr("1002428"), addr("1002428")); // p2 has space=1
		as.addRange(addr("100248c"), addr("100248c")); // different color property
		as.addRange(addr("10039dd"), addr("10039dd")); // p1 has color
		as.addRange(addr("10039f1"), addr("10039f1")); // p2 has color
		as.addRange(addr("10039fe"), addr("10039fe")); // different color property
		as = getCodeUnitSet(as, diffPlugin.getSecondProgram());
		return new ProgramSelection(getCodeUnitSet(as, program));
	}

	ProgramSelection getSetupBookmarkDiffs() {
		AddressSet as = new AddressSet();
		as.addRange(addr("100230b"), addr("100230d"));
		as.addRange(addr("1002318"), addr("1002318"));
		as = getCodeUnitSet(as, diffPlugin.getSecondProgram());
		return new ProgramSelection(getCodeUnitSet(as, program));
	}

	void getDiffDialog(String pgm1, String pgm2) throws Exception {
		openSecondProgram(pgm1, pgm2);

		invokeLater(getDiffs);

		getDiffsDialog = waitForDialogComponent(ExecuteDiffDialog.class);
		assertNotNull(getDiffsDialog);

		getDiffDialogComponents(getDiffsDialog.getComponent());
	}

	void getDiffDialog(Program pgm1, Program pgm2) throws Exception {
		openSecondProgram(pgm1, pgm2);

		invokeLater(getDiffs);

		getDiffsDialog = waitForDialogComponent(ExecuteDiffDialog.class);
		assertNotNull(getDiffsDialog);

		getDiffDialogComponents(getDiffsDialog.getComponent());
	}

	void getDiffDialogComponents(Container win) {
		programContextCB = (JCheckBox) findComponentByName(win, "ProgramContextDiffCB");
		byteCB = (JCheckBox) findComponentByName(win, "BytesDiffCB");
		codeUnitCB = (JCheckBox) findComponentByName(win, "CodeUnitsDiffCB");
		refCB = (JCheckBox) findComponentByName(win, "ReferencesDiffCB");
		commentCB = (JCheckBox) findComponentByName(win, "CommentsDiffCB");
		labelCB = (JCheckBox) findComponentByName(win, "LabelsDiffCB");
		functionCB = (JCheckBox) findComponentByName(win, "FunctionsDiffCB");
		bookmarkCB = (JCheckBox) findComponentByName(win, "BookmarksDiffCB");
		propertiesCB = (JCheckBox) findComponentByName(win, "PropertiesDiffCB");

		limitToSelectionCB = (JCheckBox) findComponentByName(win, "LimitToSelectionDiffCB");
		limitText = (JTextArea) findComponentByName(win, "AddressTextArea");
	}

	void setAllTypes(boolean select) {
		setCheckBoxes(select, new JCheckBox[] { programContextCB, byteCB, codeUnitCB, refCB,
			commentCB, labelCB, functionCB, bookmarkCB, propertiesCB });
	}

	void topOfFile(final FieldPanel fp) {
		runSwing(() -> fp.cursorTopOfFile());
	}

	void bottomOfFile(final FieldPanel fp) {
		runSwing(() -> fp.cursorBottomOfFile());
	}

	boolean isProviderShown(Window win, String title) {
		if (isLabelInContainer(win, title)) {
			return true;
		}
		Window[] wins = win.getOwnedWindows();
		for (Window element : wins) {
			if (isProviderShown(element, title)) {
				return true;
			}
		}
		return false;
	}

	boolean isLabelInContainer(Container container, String title) {
		Component[] comps = container.getComponents();
		for (Component element : comps) {
			if (element instanceof JLabel) {
				JLabel label = (JLabel) element;
				if (title.equals(label.getText())) {
					return true;
				}
			}
			else if (element instanceof Container) {
				if (isLabelInContainer((Container) element, title)) {
					return true;
				}
			}
		}
		return false;
	}

	public static AddressSet getCodeUnitSet(AddressSetView addrSet, Program program) {
		return DiffUtility.getCodeUnitSet(addrSet, program);
	}

	void setDiffSelection(final AddressSetView addrSet) {
		runSwing(() -> diffPlugin.setProgram2Selection(new ProgramSelection(addrSet)), true);
	}

	void checkIfSameSelection(ProgramSelection expectedSelection,
			ProgramSelection currentSelection) {
		AddressSet missingFromSelection = expectedSelection.subtract(currentSelection);
		AddressSet unexpectedlySelected = currentSelection.subtract(expectedSelection);
		StringBuffer buf = new StringBuffer();
		if (!missingFromSelection.isEmpty()) {
			buf.append("\nSelection expected the following addresses but they are missing: \n" +
				missingFromSelection.toString());
		}
		if (!unexpectedlySelected.isEmpty()) {
			buf.append("\nSelection unexpectedly contains the following addresses: \n" +
				unexpectedlySelected.toString());
		}
		if (buf.length() > 0) {
			String message = buf.toString();
			Assert.fail(message);
		}
		assertEquals(expectedSelection, currentSelection);
	}

	private void showProgramTree() {

		ProgramTreePlugin ptree = env.getPlugin(ProgramTreePlugin.class);
		programTreeProvider = (ComponentProvider) getInstanceField("viewProvider", ptree);
		tool.showComponentProvider(programTreeProvider, true);
	}

	JTree getProgramTree() {
		JTree tree = findComponent(programTreeProvider.getComponent(), JTree.class);
		return tree;
	}

	public DomainFile restoreProgram(Program p)
			throws InvalidNameException, CancelledException, IOException {

		DomainFolder rootFolder = env.getProject().getProjectData().getRootFolder();
		DomainFolder parent = rootFolder;
		return parent.createFile(p.getName(), p, TaskMonitor.DUMMY);
	}
//==================================================================================================
// Inner Classes
//==================================================================================================

	private class OpenVersionedFileDialogTestFake extends OpenVersionedFileDialog {

		private ActionListener listener;
		private Program chosenProgram;

		OpenVersionedFileDialogTestFake(Program program) {
			super(tool, "Select Other Program", null);
			this.chosenProgram = program;
		}

		@Override
		public void showComponent() {
			tool.showDialog(this);
		}

		@Override
		public void addOkActionListener(ActionListener l) {
			this.listener = l;
		}

		@Override
		public void close() {
			Window window = windowForComponent(getComponent());
			if (window != null) {
				window.setVisible(false);
			}
		}

		@Override
		public DomainObject getVersionedDomainObject(Object consumer, boolean readOnly) {
			return chosenProgram;
		}

		void notifyProgramChosen() {
			runSwing(() -> listener.actionPerformed(null), false);

			waitForSwing();
		}
	}
}
