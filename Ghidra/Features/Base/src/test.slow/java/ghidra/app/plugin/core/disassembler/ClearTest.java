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
package ghidra.app.plugin.core.disassembler;

import static org.junit.Assert.*;

import java.awt.Dimension;
import java.math.BigInteger;

import javax.swing.*;

import org.junit.*;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingActionIf;
import docking.widgets.fieldpanel.*;
import docking.widgets.fieldpanel.field.Field;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.clear.ClearDialog;
import ghidra.app.plugin.core.clear.ClearPlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class ClearTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String COMMENTS_CHECK_BOX_TEXT =
		"<HTML>Comments <FONT SIZE=\"2\">(does not affect automatic comments)</FONT>";

	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CodeBrowserPlugin cb;
	private DockingActionIf clearAction;
	private DockingActionIf clearWithOptionsAction;

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setupTool(tool);

		cb = env.getPlugin(CodeBrowserPlugin.class);

		showTool(tool);
		loadProgram("notepad");

		cb.updateNow();
	}

	private void setupTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(DisassemblerPlugin.class.getName());
		tool.addPlugin(ClearPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());

		ClearPlugin cp = getPlugin(tool, ClearPlugin.class);
		clearAction = getAction(cp, "Clear Code Bytes");
		clearWithOptionsAction = getAction(cp, "Clear With Options");
	}

	private void closeProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.closeProgram();
		waitForSwing();
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private void turnOffOption(String name, DialogComponentProvider provider) {
		final JCheckBox check = (JCheckBox) findAbstractButtonByText(provider.getComponent(), name);
		runSwing(() -> check.setSelected(false));
	}

	private void loadProgram(String programName) throws Exception {

		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._X86);
		program = builder.getProgram();
		addrFactory = program.getAddressFactory();

		builder.createMemory(".text1", "0x01001000", 0x6000);
		builder.createMemory(".text2", "0x01008000", 0x1000);
		builder.createMemory(".text3", "0x0100d000", 0x1000);

		builder.setBytes("0x0100d2c1", "00 00 00 01 00 03 03 44 00 65 00 26 00 6c 00");

		Structure struct = new StructureDataType("IntStruct", 0);
		struct.add(new ByteDataType());
		struct.add(new WordDataType());
		struct.add(new DWordDataType());
		struct.add(new QWordDataType());
		builder.applyDataType("0x0100d2c1", struct, 1);

		builder.setBytes("0x010026f0", "84 e0", true);
		builder.setBytes("0x010022b6", "eb 07", true);
		builder.setBytes("0x010022bf", "8b 4d 08", true);
		builder.setBytes("0x010022c4", "1b c9", true);
		builder.setBytes("0x010022cc", "0f b7 c9", true);

		builder.setBytes("0x1003305", "75 07", true);
		builder.setBytes("0x100330c", "eb 11", true);
		builder.setBytes("0x100330e", "a1 f0 98 00 01", true);
		builder.setBytes("0x1003307", "a1 e0 98 00 01", true);
		builder.setBytes("0x010032d5", "51 51 53 56", true);
		builder.setBytes("0x100331f", "66 39 1d c0 92 00 01", true);

		builder.setBytes("0x01003698", "57", true);
		builder.setBytes("0x010036a2", "8d 85 6c ff ff ff", true);
		builder.setBytes("0x010036b4", "0f 84 44 03 00 00", true);
		builder.setBytes("0x010036c0", "ff 75 fc", true);

		builder.setBytes("0x01006f50",
			"68 00 00 03 00 68 00 00 01 00 e8 31 00 00 00 83 c4 08 c3 90 90 90 90 90 90 " +
				"90 90 90 90 90 90 90 33 c0 c3 90 90 90 90 90 90 90 90 90 90 90 90 90");

		builder.setBytes("0x010058fa", "56", true);

		//
		// for clearing labels
		builder.createLabel("0x01001010", "ten");
		builder.createLabel("0x01001020", "twenty");
		builder.createExternalReference("0x01001008", "ADVAPI32.dll", "RegQueryValueExW", 0);

		//
		// For clearing bookmarks
		//
		builder.createBookmark("0x01001030", BookmarkType.INFO, "Category1", "Comment");
		builder.createBookmark("0x01001040", BookmarkType.NOTE, "Category2", "Comment");

		//
		// For clearing functions
		//
		builder.setBytes("0x01002cf5",
			"55 8b ec 83 7d 14 00 56 8b 35 e0 10 00 01 57 74 09 ff 75 14 ff d6 " +
				"8b f8 eb 02 33 ff ff 75 10 ff d6 03 c7 8d 44 00 02 50 6a 40 ff 15 dc 10 00 01 8b f0 " +
				"85 f6 74 27 56 ff 75 14 ff 75 10 e8 5c ff ff ff ff 75 18 ff 75 0c 56 ff 75 08 ff 15 " +
				"04 12 00 01 56 8b f8 ff 15 c0 10 00 01 eb 14 ff 75 18 ff 75 0c ff 75 10 ff 75 08 ff " +
				"15 04 12 00 01 8b f8 8b c7 5f 5e 5d c2 14 00");
		builder.disassemble(new AddressSet(addr("0x01002cf5"), addr("0x01002d6b")));
		builder.createFunction("0x01002cf5");

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
	}

	@Test
	public void testClearActionEnablement() throws Exception {

		closeProgram();
		assertTrue(!clearAction.isEnabledForContext(new ActionContext()));

		showTool(tool);
		loadProgram("notepad");
		cb.updateNow();
		waitForSwing();
		assertTrue(cb.goToField(addr("0x10026f0"), "Address", 0, 0));

		assertTrue(clearAction.isEnabled());
		closeProgram();

		assertTrue(!clearAction.isEnabledForContext(new ActionContext()));
	}

	@Test
	public void testClearNothing() throws Exception {

		long numInstructions = program.getListing().getNumInstructions();

		makeSelection(tool, program, addr("0x10082d8"), addr("0x10082ed"));

		doClearAction(true);

		assertEquals(numInstructions, program.getListing().getNumInstructions());

	}

	@Test
	public void testClearRangeWithUndefinedAtTop() throws Exception {

		adjustFieldPanelSize(30);

		long numInstructions = program.getListing().getNumInstructions();

		makeSelection(tool, program, addr("0x10032d2"), addr("0x10032d8"));

		doClearAction(true);

		assertEquals(numInstructions - 4, program.getListing().getNumInstructions());

	}

	@Test
	public void testClearRangeWithUndefinedScattered() throws Exception {

		long numInstructions = program.getListing().getNumInstructions();

		makeSelection(tool, program, addr("0x1006f50"), addr("0x100661f"));

		doClearAction(true);

		assertEquals(numInstructions, program.getListing().getNumInstructions());

	}

	@Test
	public void testClearCodeUnit() throws Exception {

		assertTrue(cb.goToField(addr("0x10058fa"), "Bytes", 0, 4));
		assertNotNull(program.getListing().getInstructionAt(addr("0x10058fa")));

		doClearAction(true);

		assertNull(program.getListing().getInstructionAt(addr("0x10058fa")));
	}

	/*
	 * This tests that a selection inside a structure changes the structure, but leaves it applied
	 * at the address
	 */
	@Test
	public void testClearInStructure() throws Exception {

		Data d = program.getListing().getDataAt(addr("0x100d2c1"));
		Structure s = (Structure) d.getDataType();
		assertEquals(4, s.getNumComponents());

		cb.goToField(addr("0x100d2c1"), "+", 0, 0);
		click(cb, 1);

		makeInteriorSelection_d2c1_to_d2c8();
		doClearAction(true);

		d = program.getListing().getDataAt(addr("0x100d2c1"));
		s = (Structure) d.getDataType();
		assertEquals("Did not get the expected number of components in structure", 15,
			s.getNumComponents());

		assertSame(d.getDataType(), s);
	}

	private void makeInteriorSelection_d2c1_to_d2c8() {

		Address start = addr("0x100d2c1");
		Address end = addr("0x100d2c8");
		AddressFieldLocation startLocation =
			new AddressFieldLocation(program, start, new int[] { 0 }, start.toString(), 0);
		AddressFieldLocation endLocation =
			new AddressFieldLocation(program, end, new int[] { 3 }, end.toString(), 0);
		InteriorSelection interiorSelection =
			new InteriorSelection(startLocation, endLocation, start, end);
		ProgramSelection selection = new ProgramSelection(interiorSelection);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", selection, program));
		waitForSwing();
	}

	/*
	 * This tests that a selection that includes the outermost header of does not change the 
	 * selection, but instead removes the structure from the listing at that address.
	 */
	@Test
	public void testClearStructure() throws Exception {

		Data d = program.getListing().getDataAt(addr("0x100d2c1"));
		Structure s = (Structure) d.getDataType();
		assertEquals(4, s.getNumComponents());

		cb.goToField(addr("0x100d2c1"), "+", 0, 0);
		click(cb, 1);

		makeSelection(tool, program, addr("0x100d2c1"), addr("0x100d2c8"));

		doClearAction(true);

		assertEquals(4, s.getNumComponents());
		d = program.getListing().getDataAt(addr("0x100d2c1"));
		assertNotSame(d.getDataType(), s);
	}

	@Test
	public void testClearMultiSelection() throws Exception {

		long numInst = program.getListing().getNumInstructions();

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr("0x1003698"), addr("0x10036a2"));
		selectionSet.add(addr("0x10036b4"), addr("0x10036c0"));
		ProgramSelection selection = new ProgramSelection(selectionSet);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", selection, program));

		AddressSet set = new AddressSet();
		set.addRange(addr("0x1003698"), addr("0x10036a7"));
		set.addRange(addr("0x10036b4"), addr("0x10036c2"));
		assertEquals(set, cb.getCurrentSelection());

		doClearAction(true);

		assertEquals(numInst - 4, program.getListing().getNumInstructions());
	}

	@Test
	public void testClearNotRemoveComment() throws Exception {

		SetCommentCmd cmd =
			new SetCommentCmd(addr("0x1003698"), CodeUnit.EOL_COMMENT, "my comment");
		applyCmd(program, cmd);

		CodeUnit cu = program.getListing().getCodeUnitAt(addr("0x1003698"));
		assertEquals("my comment", cu.getComment(CodeUnit.EOL_COMMENT));

		assertTrue(cb.goToField(addr("0x1003698"), "Bytes", 0, 4));
		doClearAction(true);

		cu = program.getListing().getCodeUnitAt(addr("0x1003698"));
		assertEquals("my comment", cu.getComment(CodeUnit.EOL_COMMENT));

	}

	@Test
	public void testClearNothingWithOptions() throws Exception {

		long numInstructions = program.getListing().getNumInstructions();

		makeSelection(tool, program, addr("0x10082d8"), addr("0x10082ed"));

		performAction(clearWithOptionsAction, cb.getProvider(), false);
		okOnClearDialog();

		assertEquals(numInstructions, program.getListing().getNumInstructions());
	}

	@Test
	public void testClearUnreferencedSymbol() throws Exception {

		assertTrue(cb.goToField(addr("0x10022cc"), "Bytes", 0, 4));
		AddLabelCmd cmd =
			new AddLabelCmd(addr("0x10022cc"), "Fred", false, SourceType.USER_DEFINED);
		applyCmd(program, cmd);

		performAction(clearWithOptionsAction, cb.getProvider(), false);
		ClearDialog cd = waitForDialogComponent(ClearDialog.class);

		turnOffOption(COMMENTS_CHECK_BOX_TEXT, cd);
		turnOffOption("Properties", cd);
		turnOffOption("Code", cd);
		turnOffOption("Functions", cd);
		turnOffOption("Registers", cd);
		turnOffOption("Equates", cd);
		turnOffOption("Bookmarks", cd);

		okOnClearDialog();
		waitForBusyTool(tool);
		program.flushEvents();
		waitForSwing();

		assertEquals(0, program.getSymbolTable().getSymbols(addr("0x10022cc")).length);
		undo(program);
		assertEquals(1, program.getSymbolTable().getSymbols(addr("0x10022cc")).length);
	}

	@Test
	public void testClearReferencedSymbolAndReferingCodeUnit() throws Exception {

		adjustFieldPanelSize(40);

		makeSelection(tool, program, addr("0x10022b6"), addr("0x10022c4"));

		performAction(clearWithOptionsAction, cb.getProvider(), false);
		ClearDialog cd = waitForDialogComponent(ClearDialog.class);

		turnOffOption(COMMENTS_CHECK_BOX_TEXT, cd);
		turnOffOption("Properties", cd);
		turnOffOption("Functions", cd);
		turnOffOption("Registers", cd);
		turnOffOption("Equates", cd);
		turnOffOption("Bookmarks", cd);

		okOnClearDialog();
		waitForBusyTool(tool);
		program.flushEvents();
		waitForSwing();

		assertEquals(0, program.getSymbolTable().getSymbols(addr("0x10022bf")).length);
		undo(program);
		assertEquals(1, program.getSymbolTable().getSymbols(addr("0x10022bf")).length);
	}

	@Test
	public void testClearReferencedSymbol() throws Exception {

		adjustFieldPanelSize(40);

		Symbol[] symbols = program.getSymbolTable().getSymbols(addr("0x10022bf"));
		Symbol s = symbols[0];
		RenameLabelCmd cmd = new RenameLabelCmd(s.getAddress(), s.getName(), "Fred",
			s.getParentNamespace(), SourceType.USER_DEFINED);
		applyCmd(program, cmd);

		makeSelection(tool, program, addr("0x10022bf"), addr("0x10022c4"));

		performAction(clearWithOptionsAction, cb.getProvider(), false);
		ClearDialog cd = waitForDialogComponent(ClearDialog.class);

		turnOffOption(COMMENTS_CHECK_BOX_TEXT, cd);
		turnOffOption("Properties", cd);
		turnOffOption("Functions", cd);
		turnOffOption("Code", cd);
		turnOffOption("Registers", cd);
		turnOffOption("Equates", cd);
		turnOffOption("Bookmarks", cd);

		okOnClearDialog();

		symbols = program.getSymbolTable().getSymbols(addr("0x10022bf"));
		assertEquals(1, symbols.length);
		assertEquals("LAB_010022bf", symbols[0].getName());
		undo(program);
		symbols = program.getSymbolTable().getSymbols(addr("0x10022bf"));
		assertEquals(1, symbols.length);
		assertEquals("Fred", symbols[0].getName());
	}

	@Test
	public void testClearSymbolsDoesNotClearAnchoredSymbols() throws Exception {

		Symbol[] symbols = program.getSymbolTable().getSymbols(addr("0x01001010"));
		assertEquals(1, symbols.length);
		assertTrue(!symbols[0].isDynamic());
		int id = program.startTransaction("Anchor");
		symbols[0].setPinned(true);
		program.endTransaction(id, true);

		makeSelection(tool, program, addr("0x01001010"), addr("0x01001020"));

		performAction(clearWithOptionsAction, cb.getProvider(), false);

		waitForDialogComponent(ClearDialog.class);
		okOnClearDialog();

		symbols = program.getSymbolTable().getSymbols(addr("0x01001010"));
		assertEquals(1, symbols.length);
		assertTrue(!symbols[0].isDynamic());
	}

	@Test
	public void testClearSystemReferences() throws Exception {

		adjustFieldPanelSize(40);

		makeSelection(tool, program, addr("0x1003305"), addr("0x100330e"));

		performAction(clearWithOptionsAction, cb.getProvider(), false);

		Reference[] refs = program.getReferenceManager().getReferencesFrom(addr("0x1003307"));
		assertEquals(1, refs.length);

		ClearDialog cd = waitForDialogComponent(ClearDialog.class);

		turnOffOption(COMMENTS_CHECK_BOX_TEXT, cd);
		turnOffOption("Properties", cd);
		turnOffOption("Functions", cd);
		turnOffOption("Code", cd);
		turnOffOption("Registers", cd);
		turnOffOption("Equates", cd);
		turnOffOption("Bookmarks", cd);
		turnOffOption("User-defined References", cd);

		okOnClearDialog();

		Symbol[] symbols = program.getSymbolTable().getSymbols(addr("0x100330e"));
		assertEquals(0, symbols.length);

		symbols = program.getSymbolTable().getSymbols(addr("0x100331f"));
		assertEquals(0, symbols.length);

		assertEquals(0, program.getReferenceManager().getReferencesFrom(addr("0x1003307")).length);
	}

	@Test
	public void testNoClearSystemReferences() throws Exception {

		Symbol[] symbols = program.getSymbolTable().getSymbols(addr("0x100331f"));
		assertEquals(1, symbols.length);

		Reference[] refs = program.getReferenceManager().getReferencesFrom(addr("0x1003307"));
		assertEquals(1, refs.length);

		makeSelection(tool, program, addr("0x1003305"), addr("0x100330e"));

		performAction(clearWithOptionsAction, cb.getProvider(), false);
		ClearDialog cd = waitForDialogComponent(ClearDialog.class);

		turnOffOption(COMMENTS_CHECK_BOX_TEXT, cd);
		turnOffOption("Properties", cd);
		turnOffOption("Functions", cd);
		turnOffOption("Code", cd);
		turnOffOption("Registers", cd);
		turnOffOption("Equates", cd);
		turnOffOption("Bookmarks", cd);
		turnOffOption("Default References", cd);

		okOnClearDialog();

		symbols = program.getSymbolTable().getSymbols(addr("0x100330e"));
		assertEquals(1, symbols.length);

		symbols = program.getSymbolTable().getSymbols(addr("0x100331f"));
		assertEquals(1, symbols.length);

		assertEquals(1, program.getReferenceManager().getReferencesFrom(addr("0x1003307")).length);
	}

	@Test
	public void testClearAllWithOptions() throws Exception {

		// 2 user defined labels
		// 1 external with it's symbol
		// 1 function with it's label
		assertEquals(6, program.getSymbolTable().getNumSymbols());

		DockingActionIf action = getAction(cb, "Select All");
		performAction(action, cb.getProvider(), true);

		performAction(clearWithOptionsAction, cb.getProvider(), false);
		okOnClearDialog();

		Listing l = program.getListing();
		assertEquals(0, l.getNumInstructions());
		assertEquals(0, l.getNumDefinedData());

		assertEquals(0, program.getBookmarkManager().getBookmarkCount());

		// External libraries and associated symbols will remain
		assertEquals(2, program.getSymbolTable().getNumSymbols());
	}

	@Test
	public void testClearComments() throws Exception {

		assertTrue(cb.goToField(addr("0x10022cc"), "Bytes", 0, 4));
		SetCommentCmd cmd =
			new SetCommentCmd(addr("0x10022cc"), CodeUnit.EOL_COMMENT, "my comment");
		applyCmd(program, cmd);

		performAction(clearWithOptionsAction, cb.getProvider(), false);
		ClearDialog cd = waitForDialogComponent(ClearDialog.class);
		turnOffOption("Code", cd);

		okOnClearDialog();

		CodeUnit cu = program.getListing().getCodeUnitAt(addr("0x10022cc"));

		assertNull(cu.getComment(CodeUnit.EOL_COMMENT));
		undo(program);
		assertNotNull(cu.getComment(CodeUnit.EOL_COMMENT));
		redo(program);
		assertNull(cu.getComment(CodeUnit.EOL_COMMENT));

	}

	@Test
	public void testClearBookmarks() throws Exception {

		assertTrue(program.getBookmarkManager().getBookmarkCount() > 0);

		final DockingActionIf action = getAction(cb, "Select All");
		performAction(action, cb.getProvider(), true);

		performAction(clearWithOptionsAction, cb.getProvider(), false);
		ClearDialog cd = waitForDialogComponent(ClearDialog.class);
		turnOffOption(COMMENTS_CHECK_BOX_TEXT, cd);
		turnOffOption("Properties", cd);
		turnOffOption("Functions", cd);
		turnOffOption("Registers", cd);
		turnOffOption("Equates", cd);
		turnOffOption("Code", cd);
		turnOffOption("Symbols", cd);

		okOnClearDialog();

		Listing l = program.getListing();
		assertTrue(l.getNumInstructions() > 0);
		assertTrue(l.getNumDefinedData() > 0);

		assertEquals(0, program.getBookmarkManager().getBookmarkCount());

		assertTrue(program.getSymbolTable().getNumSymbols() > 0);
	}

	@Test
	public void testClearFunctions() throws Exception {

		assertTrue(program.getListing().getFunctions(true).hasNext());

		DockingActionIf action = getAction(cb, "Select All");
		performAction(action, cb.getProvider(), true);

		performAction(clearWithOptionsAction, cb.getProvider(), false);
		ClearDialog cd = waitForDialogComponent(ClearDialog.class);
		turnOffOption(COMMENTS_CHECK_BOX_TEXT, cd);
		turnOffOption("Properties", cd);
		turnOffOption("Bookmarks", cd);
		turnOffOption("Registers", cd);
		turnOffOption("Equates", cd);
		turnOffOption("Code", cd);
		turnOffOption("Symbols", cd);

		okOnClearDialog();

		Listing l = program.getListing();
		assertTrue(l.getNumInstructions() > 0);
		assertTrue(l.getNumDefinedData() > 0);

		assertTrue(!program.getListing().getFunctions(true).hasNext());

		assertTrue(program.getSymbolTable().getNumSymbols() > 0);
		undo(program);
		assertTrue(program.getListing().getFunctions(true).hasNext());

	}

	@Test
	public void testClearRegisters() throws Exception {

		assertTrue(program.getListing().getFunctions(true).hasNext());

		assertTrue(cb.goToField(addr("0x10022cc"), "Bytes", 0, 4));
		ProgramContext context = program.getProgramContext();
		Register ax = context.getRegister("AX");
		SetRegisterCmd cmd =
			new SetRegisterCmd(ax, addr("0x10022cc"), addr("0x10022ce"), BigInteger.valueOf(5));
		applyCmd(program, cmd);

		assertTrue(context.hasValueOverRange(ax, BigInteger.valueOf(5),
			new AddressSet(addr("0x10022cc"))));

		performAction(clearWithOptionsAction, cb.getProvider(), false);
		ClearDialog cd = waitForDialogComponent(ClearDialog.class);
		turnOffOption(COMMENTS_CHECK_BOX_TEXT, cd);
		turnOffOption("Properties", cd);
		turnOffOption("Bookmarks", cd);
		turnOffOption("Functions", cd);
		turnOffOption("Equates", cd);
		turnOffOption("Code", cd);
		turnOffOption("Symbols", cd);

		okOnClearDialog();

		assertTrue(!context.hasValueOverRange(ax, BigInteger.valueOf(5),
			new AddressSet(addr("0x10022cc"))));
		undo(program);
		assertTrue(context.hasValueOverRange(ax, BigInteger.valueOf(5),
			new AddressSet(addr("0x10022cc"))));
	}

	@Test
	public void testClearEquates() throws Exception {

		assertTrue(program.getListing().getFunctions(true).hasNext());

		assertTrue(cb.goToField(addr("0x10022c6"), "Bytes", 0, 4));

		SetEquateCmd cmd = new SetEquateCmd("FRED", addr("0x10022c6"), 1, 0x1000);
		applyCmd(program, cmd);

		assertEquals(1, program.getEquateTable().getEquates(0x1000).size());

		performAction(clearWithOptionsAction, cb.getProvider(), false);
		ClearDialog cd = waitForDialogComponent(ClearDialog.class);
		turnOffOption(COMMENTS_CHECK_BOX_TEXT, cd);
		turnOffOption("Properties", cd);
		turnOffOption("Bookmarks", cd);
		turnOffOption("Functions", cd);
		turnOffOption("Registers", cd);
		turnOffOption("Code", cd);
		turnOffOption("Symbols", cd);

		okOnClearDialog();

		assertEquals(0, program.getEquateTable().getEquates(0x1000).size());
		undo(program);
		assertEquals(1, program.getEquateTable().getEquates(0x1000).size());

	}

	private void okOnClearDialog() {
		ClearDialog cd = waitForDialogComponent(ClearDialog.class);

		runSwing(() -> cd.okCallback());

		waitForBusyTool(tool);
		program.flushEvents();
		waitForSwing();
	}

	private void doClearAction(boolean doWait) throws Exception {
		ActionContext actionContext = cb.getProvider().getActionContext(null);
		performAction(clearAction, actionContext, doWait);

		waitForBusyTool(tool);
		program.flushEvents();
		waitForSwing();
	}

	private void adjustFieldPanelSize(int numRows) {
		final FieldPanel fp = cb.getFieldPanel();
		JViewport vp = (JViewport) fp.getParent().getParent();
		cb.updateNow();
		int rowSize = getRowSize(fp);
		final int desiredViewportHeight = rowSize * numRows;
		final Dimension d = vp.getExtentSize();
		if (d.height != desiredViewportHeight) {
			runSwing(() -> {
				JFrame f = tool.getToolFrame();
				Dimension d2 = f.getSize();
				d2.height += desiredViewportHeight - d.height;
				f.setSize(d2);
				fp.invalidate();
				f.validate();
			});
		}
		cb.updateNow();

	}

	private int getRowSize(FieldPanel fp) {
		int rowHeight = 0;
		LayoutModel layoutModel = fp.getLayoutModel();
		Layout layout = layoutModel.getLayout(BigInteger.ZERO);
		for (int i = 0; i < layout.getNumFields(); i++) {
			Field field = layout.getField(i);
			int numRows = field.getNumRows();
			int fieldRowHeight = field.getHeight() / numRows;
			rowHeight = Math.max(rowHeight, fieldRowHeight);
		}
		return rowHeight;
	}
}
