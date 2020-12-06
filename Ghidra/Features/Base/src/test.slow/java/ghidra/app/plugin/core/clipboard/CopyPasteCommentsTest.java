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
package ghidra.app.plugin.core.clipboard;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.label.DeleteLabelCmd;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.ClipboardContentProviderService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.viewer.field.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.AddressFieldLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;

/**
 * Test the plugin that deals with cut/paste comments and labels
 */
public class CopyPasteCommentsTest extends AbstractProgramBasedTest {

	private PluginTool toolOne;
	private PluginTool toolTwo;
	private ProgramDB programOne;
	private ProgramDB programTwo;
	private ProgramManager pmOne;
	private ProgramManager pmTwo;
	private CodeBrowserPlugin cb;
	private CodeBrowserPlugin cb2;

	@Override
	protected Program getProgram() throws Exception {
		return buildProgram("sdk");
	}

	private Program buildProgram(String name) throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder(name, true, ProgramBuilder._TOY);
		builder.createMemory("test1", "0x0000", 0x2000);
		builder.createLabel("0x32d", "RSR05");
		builder.createLabel("0x331", "RSR10");
		builder.createLabel("0x31b", "RSTOR()");

		builder.addBytesFallthrough("0x0326");
		builder.createComment("0x0326", "Hey There", CodeUnit.EOL_COMMENT);
		builder.createComment("0x0182", "SAVE register 'I'", CodeUnit.EOL_COMMENT);
		builder.createComment("0x0334", "Set the SP to RAM:ESAV", CodeUnit.EOL_COMMENT);
		builder.createComment("0x0335", "RESTORE register 'DE'", CodeUnit.EOL_COMMENT);
		builder.createComment("0x0336", "RESTORE register 'BC'", CodeUnit.EOL_COMMENT);
		builder.createComment("0x0337", "RESTORE register 'A' and FLAGS", CodeUnit.EOL_COMMENT);
		builder.createComment("0x0338", "RESTORE register 'SP'", CodeUnit.EOL_COMMENT);

		builder.createMemoryReference("0x1000", "0x331", RefType.UNCONDITIONAL_JUMP,
			SourceType.DEFAULT);
		builder.createMemoryReference("0x1000", "0x31b", RefType.UNCONDITIONAL_JUMP,
			SourceType.DEFAULT);

		return builder.getProgram();
	}

	@Before
	public void setUp() throws Exception {

		initialize();

		toolOne = tool;
		setupTool(toolOne);
		cb = codeBrowser;

		toolTwo = env.launchAnotherDefaultTool();
		setupTool(toolTwo);
		cb2 = getPlugin(toolTwo, CodeBrowserPlugin.class);

		DomainFolder rootFolder = env.getProject().getProjectData().getRootFolder();

		Program sdk = program;
		final DomainFile df = rootFolder.createFile("sdk1", sdk, TaskMonitor.DUMMY);
		programOne = (ProgramDB) df.getDomainObject(this, true, false, TaskMonitor.DUMMY);
		env.release(sdk);

		Program sdk2 = buildProgram("sdk2");
		final DomainFile df2 = rootFolder.createFile("sdk2", sdk2, TaskMonitor.DUMMY);
		programTwo = (ProgramDB) df2.getDomainObject(this, true, false, TaskMonitor.DUMMY);
		env.release(sdk2);

		setupProgramOne();
		setupProgramTwo();

		pmOne = toolOne.getService(ProgramManager.class);
		runSwing(() -> {
			pmOne.openProgram(df);
			programOne = (ProgramDB) pmOne.getCurrentProgram();
		});

		pmTwo = toolTwo.getService(ProgramManager.class);
		runSwing(() -> {
			pmTwo.openProgram(df2);
			programTwo = (ProgramDB) pmTwo.getCurrentProgram();
		});

	}

	@Test
	public void testActivation() throws Exception {
		goTo(toolTwo, 0x0326);

		makeSelection(toolTwo, programTwo, addr(programTwo, 0x0331), addr(programTwo, 0x0334));

		copyToolTwoLabels();

		goTo(toolOne, 0x32a);

		ClipboardPlugin plugin = getPlugin(toolOne, ClipboardPlugin.class);
		ClipboardContentProviderService service = getClipboardService(plugin);
		DockingActionIf pasteAction = getLocalAction(service, "Paste", plugin);
		assertEnabled(pasteAction, cb.getProvider());
	}

	@Test
	public void testCopyPasteComments() {

		// in Browser(2), select an instruction that has comments but no label
		//  (0x0326);
		Address addr = addr(programTwo, 0x0326);
		goTo(toolTwo, addr.getOffset());

		toolTwo.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(addr, addr), programTwo));

		copyToolTwoLabels();

		// in Browser(1), go to 0x34e
		goTo(toolOne, 0x34e);

		pasteToolOne();

		// plate, post, and eol comments should exist now
		// in Browser(1), go to 0x182 where there is an EOL comment
		goTo(toolOne, 0x182);

		// should append EOL comment to existing comment
		pasteToolOne();

		cb.goToField(addr(programOne, 0x0182), PlateFieldFactory.FIELD_NAME, 0, 0);
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertTrue(f.getText().indexOf("* More Plate Comments (1)") > 0);

		cb.goToField(addr(programOne, 0x0182), PostCommentFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("More Post comments (1)", f.getText());

		cb.goToField(addr(programOne, 0x0182), EolCommentFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("SAVE register 'I'", f.getFieldElement(0, 0).getText());
		assertEquals("More EOL comments (1)", f.getFieldElement(1, 0).getText());
	}

	@Test
	public void testCopyPasteLabels() throws Exception {

		// in Program One, add MyLabel at 032a

		int transactionID = programOne.startTransaction("test");
		programOne.getSymbolTable()
				.createLabel(addr(programOne, 0x032a), "MyLabel",
					SourceType.USER_DEFINED);
		programOne.endTransaction(transactionID, true);

		goTo(toolTwo, 0x0326);

		// in Browser(2) select the range 0331 through 0334, (contains label RSR10)
		makeSelection(toolTwo, programTwo, addr(programTwo, 0x0331), addr(programTwo, 0x0334));

		copyToolTwoLabels();

		goTo(toolOne, 0x32a);

		pasteToolOne();

		// the label should be added
		Symbol symbol = getUniqueSymbol(programOne, "RSR10", null);
		assertNotNull(symbol);
		assertEquals(addr(programOne, 0x32a), symbol.getAddress());
		assertNotNull(getUniqueSymbol(programOne, "MyLabel", null));

		cb.goToField(addr(programOne, 0x032a), LabelFieldFactory.FIELD_NAME, 0, 0);
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals("RSR10", f.getFieldElement(0, 0).getText());
		assertEquals("MyLabel", f.getFieldElement(1, 0).getText());

		cb.goToField(addr(programOne, 0x032d), EolCommentFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("Set the SP to RAM:ESAV", f.getText());

		undo(programOne);
		cb.goToField(addr(programOne, 0x032a), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("MyLabel", f.getText());
		assertTrue(
			!cb.goToField(addr(programOne, 0x032d), EolCommentFieldFactory.FIELD_NAME, 0, 0));

		redo(programOne);
		cb.goToField(addr(programOne, 0x032a), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("RSR10", f.getFieldElement(0, 0).getText());
		assertEquals("MyLabel", f.getFieldElement(1, 0).getText());
	}

	@Test
	public void testCopyPasteDefaultLabel() {
		// verify default labels are not copied

		Symbol symbol = programTwo.getSymbolTable().getPrimarySymbol(addr(programTwo, 0x0331));
		assertNotNull(symbol);

		// in Browser(2), delete the label at 331 (a default label is created)
		// in Browser(2), select the code unit over range 331 through 334,
		// containing the default label.
		toolTwo.execute(new DeleteLabelCmd(addr(programTwo, 0x0331), "RSR10"), programTwo);
		symbol = programTwo.getSymbolTable().getPrimarySymbol(addr(programTwo, 0x0331));
		assertTrue(symbol.getSource() == SourceType.DEFAULT);

		goTo(toolTwo, 0x0331);

		makeSelection(toolTwo, programTwo, addr(programTwo, 0x0331), addr(programTwo, 0x0334));

		copyToolTwoLabels();

		// in Browser(1), go to 032a
		goTo(toolOne, 0x32a);

		pasteToolOne();

		Namespace ns = programOne.getSymbolTable().getNamespace(addr(programOne, 0x32a));
		assertEquals(ns, programOne.getGlobalNamespace());
		Symbol[] symbols = programOne.getSymbolTable().getSymbols(addr(programOne, 0x32a));
		assertEquals(0, symbols.length);

		// should be no label at 032a
		assertTrue(!cb.goToField(addr(programOne, 0x032a), LabelFieldFactory.FIELD_NAME, 0, 0));
	}

	@Test
	public void testPasteLocalLabelNoFunction() throws Exception {
		// in Browser(2), select code units 032d through 0334.
		// copy
		goTo(toolTwo, 0x0326);

		Address addr = addr(programTwo, 0x0326);

		makeSelection(toolTwo, programTwo, addr(programTwo, 0x032d), addr(programTwo, 0x0334));

		copyToolTwoLabels();

		// in Browser(1), go to 032d
		// paste
		// verify that the default label at 0331 is replaced by RSR10;
		// the default label at 032d is removed
		goTo(toolOne, 0x032d);

		pasteToolOne();

		Symbol symbol = getUniqueSymbol(programOne, "RSR10", null);
		assertNotNull(symbol);
		assertTrue(symbol.getSource() != SourceType.DEFAULT);

		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals("RSR10", f.getText());

		addr = addr(programOne, 0x032d);
		Symbol[] symbols = programOne.getSymbolTable().getSymbols(addr);
		assertEquals(1, symbols.length);
		symbol = symbols[0];
		cb.goToField(addr, LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals(symbol.getName(), f.getText());

		undo(programOne);
		//default label should come back at 331
		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals(1, f.getNumRows());

		symbols = programOne.getSymbolTable().getSymbols(addr(programOne, 0x331));
		assertEquals(1, symbols.length);
		assertEquals(symbols[0].getName(), f.getText());

		redo(programOne);
		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("RSR10", f.getText());

	}

	@Test
	public void testPasteAtExistingDefaultLabel() throws Exception {

		// in Browser(2) select 331 through 334, contains "RSR10"
		goTo(toolTwo, 0x0331);

		makeSelection(toolTwo, programTwo, addr(programTwo, 0x0331), addr(programTwo, 0x0334));

		copyToolTwoLabels();

		// in Browser(1) go to 331 -- should contain a default label
		goTo(toolOne, 0x0331);

		Symbol[] symbols = programOne.getSymbolTable().getSymbols(addr(programOne, 0x0331));

		assertTrue(symbols[0].getSource() == SourceType.DEFAULT);

		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals(symbols[0].getName(), f.getText());

		pasteToolOne();

		// default label should be replaced by RSR10
		assertNull(
			programOne.getSymbolTable().getSymbol("LAB_0331", addr(programOne, 0x0331), null));
		Symbol symbol = getUniqueSymbol(programOne, "RSR10", null);
		assertNotNull(symbol);

		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals(symbol.getName(), f.getText());

		undo(programOne);
		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		symbols = programOne.getSymbolTable().getSymbols(addr(programOne, 0x0331));
		assertEquals(1, symbols.length);
		assertEquals(symbols[0].getName(), f.getText());

		redo(programOne);
		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("RSR10", f.getText());
	}

	@Test
	public void testPasteAtUserLabel() throws Exception {

		// in Browser(2) select 331 through 334, contains "RSR10"
		goTo(toolTwo, 0x0331);

		makeSelection(toolTwo, programTwo, addr(programTwo, 0x0331), addr(programTwo, 0x0334));

		copyToolTwoLabels();

		Symbol symbol =
			programOne.getSymbolTable().getSymbol("LAB_0331", addr(programOne, 0x0331), null);
		// in Browser(1) change default label at 331 to JUNK
		int transactionID = programOne.startTransaction("test");
		programOne.getSymbolTable()
				.createLabel(addr(programOne, 0x0331), "JUNK",
					SourceType.USER_DEFINED);
		programOne.endTransaction(transactionID, true);
		//
		// in Browser(1) go to 331
		goTo(toolOne, 0x331);

		pasteToolOne();

		// verify that RSR10 and JUNK exist
		symbol = getUniqueSymbol(programOne, "RSR10", null);
		assertNotNull(symbol);
		assertEquals(addr(programOne, 0x331), symbol.getAddress());
		symbol = getUniqueSymbol(programOne, "JUNK", null);
		assertNotNull(symbol);
		assertEquals(addr(programOne, 0x331), symbol.getAddress());

		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals(2, f.getNumRows());
		assertEquals("RSR10", f.getFieldElement(0, 0).getText());
		assertEquals("JUNK", f.getFieldElement(1, 0).getText());

		undo(programOne);
		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("JUNK", f.getText());

		redo(programOne);
		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();

		assertEquals(2, f.getNumRows());
		assertEquals("RSR10", f.getFieldElement(0, 0).getText());
		assertEquals("JUNK", f.getFieldElement(1, 0).getText());
	}

	@Test
	public void testPasteAtMultipleLabels() throws Exception {
		// in program 2, create a second label, JUNK2, at 0331
		int transactionID = programOne.startTransaction("test");
		programOne.getSymbolTable()
				.createLabel(addr(programOne, 0x331), "JUNK2",
					SourceType.USER_DEFINED);
		programOne.endTransaction(transactionID, true);

		// in Browser(2) select 331 through 334, contains "RSR10"
		goTo(toolTwo, 0x0331);

		makeSelection(toolTwo, programTwo, addr(programTwo, 0x0331), addr(programTwo, 0x0334));

		copyToolTwoLabels();

		// in Browser(1) go to 331
		goTo(toolOne, 0x331);

		pasteToolOne();

		// verify that the dynamic symbol is replaced with RSR10 and JUNK2
		Symbol symbol = getUniqueSymbol(programOne, "RSR10", null);
		assertNotNull(symbol);
		assertEquals(addr(programOne, 0x331), symbol.getAddress());
		symbol = getUniqueSymbol(programOne, "JUNK2", null);
		assertNotNull(symbol);
		assertEquals(addr(programOne, 0x331), symbol.getAddress());

		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals(2, f.getNumRows());

		undo(programOne);
		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		Symbol[] symbols = programOne.getSymbolTable().getSymbols(addr(programOne, 0x0331));
		assertEquals(1, symbols.length);

		assertEquals(symbols[0].getName(), f.getText());

		redo(programOne);
		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals(2, f.getNumRows());
		assertEquals("RSR10", f.getFieldElement(0, 0).getText());
		assertEquals("JUNK2", f.getFieldElement(1, 0).getText());

	}

	@Test
	public void testPasteWhereUserLabelExists() throws Exception {
		int transactionID = programOne.startTransaction("test");
		programOne.getSymbolTable()
				.createLabel(addr(programOne, 0x331), "JUNK2",
					SourceType.USER_DEFINED);
		programOne.endTransaction(transactionID, true);

		// in Browser(2) select 331 through 334, contains "RSR10"
		goTo(toolTwo, 0x0331);

		makeSelection(toolTwo, programTwo, addr(programTwo, 0x0331), addr(programTwo, 0x0334));

		copyToolTwoLabels();

		// in Browser(1) go to 331
		goTo(toolOne, 0x331);

		pasteToolOne();

		// verify that the dynamic symbol is replaced with RSR10 and JUNK2
		Symbol symbol = getUniqueSymbol(programOne, "RSR10", null);
		assertNotNull(symbol);
		assertEquals(addr(programOne, 0x331), symbol.getAddress());
		symbol = getUniqueSymbol(programOne, "JUNK2", null);
		assertNotNull(symbol);
		assertEquals(addr(programOne, 0x331), symbol.getAddress());
		assertNull(
			programOne.getSymbolTable().getSymbol("LAB_0331", addr(programOne, 0x0331), null));

		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals(2, f.getNumRows());
		assertEquals("RSR10", f.getFieldElement(0, 0).getText());
		assertEquals("JUNK2", f.getFieldElement(1, 0).getText());

		// paste again; labels should remain unaffected by the paste since they already exist
		pasteToolOne();
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("RSR10", f.getFieldElement(0, 0).getText());
		assertEquals("JUNK2", f.getFieldElement(1, 0).getText());

		undo(programOne);
		undo(programOne);
		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("JUNK2", f.getText());

		redo(programOne);
		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals(2, f.getNumRows());
		assertEquals("RSR10", f.getFieldElement(0, 0).getText());
		assertEquals("JUNK2", f.getFieldElement(1, 0).getText());

	}

	@Test
	public void testPasteNonContiguousSelection() throws Exception {
		// in Browser(1) add a pre comment at 331
		CodeUnit cu = programOne.getListing().getCodeUnitAt(addr(programOne, 0x331));
		int transactionID = programOne.startTransaction("test");
		cu.setComment(CodeUnit.PRE_COMMENT, "my pre comment for this test");
		programOne.endTransaction(transactionID, true);
		waitForSwing();

		// in Browser(2) select 031b and 0331
		goTo(toolTwo, 0x031b);

		AddressSet set = new AddressSet();
		set.addRange(addr(programTwo, 0x31b), addr(programTwo, 0x31d));
		set.addRange(addr(programTwo, 0x331), addr(programTwo, 0x333));

		makeSelection(toolTwo, programTwo, set);

		copyToolTwoLabels();

		// in Browser(1) go to 31b
		goTo(toolOne, 0x31b);

		pasteToolOne();

		// verify the labels are copied
		assertNull(
			programOne.getSymbolTable().getSymbol("LAB_0331", addr(programOne, 0x0331), null));
		Symbol symbol = getUniqueSymbol(programOne, "RSTOR()", null);
		assertNotNull(symbol);
		assertEquals(addr(programOne, 0x31b), symbol.getAddress());
		assertNull(
			programOne.getSymbolTable().getSymbol("LAB_0331", addr(programOne, 0x0331), null));
		symbol = getUniqueSymbol(programOne, "RSR10", null);
		assertNotNull(symbol);
		assertEquals(addr(programOne, 0x331), symbol.getAddress());

		// verify pre comment at 331 remains unaffected
		cu = programOne.getListing().getCodeUnitAt(addr(programOne, 0x331));
		assertEquals("my pre comment for this test", cu.getComment(CodeUnit.PRE_COMMENT));

		// verify browser field

		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals("RSR10", f.getText());

		cb.goToField(addr(programOne, 0x031b), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("RSTOR()", f.getText());

		cb.goToField(addr(programOne, 0x0331), "Pre-Comment", 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("my pre comment for this test", f.getText());

		undo(programOne);

		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals(programOne.getSymbolTable()
				.getSymbol("LAB_00000331", addr(programOne, 0x0331),
					null)
				.getName(),
			f.getText());

		cb.goToField(addr(programOne, 0x031b), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals(programOne.getSymbolTable()
				.getSymbol("LAB_0000031b", addr(programOne, 0x031b),
					null)
				.getName(),
			f.getText());

		redo(programOne);

		cb.goToField(addr(programOne, 0x0331), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("RSR10", f.getText());

		cb.goToField(addr(programOne, 0x031b), LabelFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("RSTOR()", f.getText());
	}

	@Test
	public void testPasteFunctionLabelsComments() throws Exception {

		// in program(1) create a function with body 031b through 343
		Address min = addr(programOne, 0x31b);
		Address max = addr(programOne, 0x0343);
		Listing listing = programOne.getListing();

		// create a function over the range 0x31b through 0x0343.		
		int transactionID = programOne.startTransaction("test");
		String name = SymbolUtilities.getDefaultFunctionName(min);
		programOne.getListing()
				.createFunction(name, min, new AddressSet(min, max),
					SourceType.USER_DEFINED);
		programOne.endTransaction(transactionID, true);
		programOne.flushEvents();
		waitForSwing();

		// in Browser(2) select 31b through 343
		goTo(toolTwo, 0x031b);

		makeSelection(toolTwo, programTwo, addr(programTwo, 0x031b), addr(programTwo, 0x0334));

		copyToolTwoLabels();

		// in Browser(1) go to 031b
		goTo(toolOne, 0x31b);

		pasteToolOne();

		// verify comments are copied
		CodeUnit cu = listing.getCodeUnitAt(addr(programOne, 0x0320));
		assertEquals("My Plate Comment", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("My Post comment", cu.getComment(CodeUnit.POST_COMMENT));

		cu = listing.getCodeUnitAt(addr(programOne, 0x326));
		assertEquals("More Plate Comments (1)", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("More Post comments (1)", cu.getComment(CodeUnit.POST_COMMENT));
		assertEquals("More EOL comments (1)", cu.getComment(CodeUnit.EOL_COMMENT));

		cu = listing.getCodeUnitAt(addr(programOne, 0x32a));
		assertEquals("More Plate Comments (2)", cu.getComment(CodeUnit.PLATE_COMMENT));
		assertEquals("More Post comments (2)", cu.getComment(CodeUnit.POST_COMMENT));
		assertEquals("More EOL comments (2)", cu.getComment(CodeUnit.EOL_COMMENT));

		cb.goToField(addr(programOne, 0x0320), PlateFieldFactory.FIELD_NAME, 0, 0);
		ListingTextField f = (ListingTextField) cb.getCurrentField();
		assertEquals(3, f.getNumRows());
		assertTrue(f.getText().indexOf("My Plate Comment") > 0);

		cb.goToField(addr(programOne, 0x0320), PostCommentFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("My Post comment", f.getText());

		cb.goToField(addr(programOne, 0x0326), PlateFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals(3, f.getNumRows());
		assertTrue(f.getText().indexOf("More Plate Comments (1)") > 0);

		cb.goToField(addr(programOne, 0x0326), PostCommentFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("More Post comments (1)", f.getText());

		cb.goToField(addr(programOne, 0x032a), EolCommentFieldFactory.FIELD_NAME, 0, 0);
		f = (ListingTextField) cb.getCurrentField();
		assertEquals("More EOL comments (2)", f.getText());
	}

	@Test
	public void testDuplicateComments() {
		// verify that comments are not duplicated in the paste
		// in Browser(2) select 334 through 33b
		goTo(toolTwo, 0x0334);

		makeSelection(toolTwo, programTwo, addr(programTwo, 0x0334), addr(programTwo, 0x033b));

		copyToolTwoLabels();

		// in Browser(1) go to 334
		goTo(toolOne, 0x334);

		pasteToolOne();

		String[] comments = new String[] { "Set the SP to RAM:ESAV", "RESTORE register 'DE'",
			"RESTORE register 'BC'", "RESTORE register 'A' and FLAGS", "RESTORE register 'SP'" };

		Listing listing = programOne.getListing();

		Address addr = addr(programOne, 0x334);
		for (String element : comments) {
			CodeUnit cu = listing.getCodeUnitAt(addr);
			assertEquals(element, cu.getComment(CodeUnit.EOL_COMMENT));
			assertTrue(cb.goToField(addr, EolCommentFieldFactory.FIELD_NAME, 0, 0));
			ListingTextField f = (ListingTextField) cb.getCurrentField();
			assertEquals(element, f.getText());
			addr = addr.add(1);
		}
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void copyToolTwoLabels() {
		ClipboardPlugin plugin = getPlugin(toolTwo, ClipboardPlugin.class);
		ClipboardContentProviderService service =
			getClipboardService(plugin);
		DockingAction action = getLocalAction(service, "Copy Special", plugin);
		assertNotNull(action);
		assertEnabled(action, cb2.getProvider());

		runSwing(
			() -> plugin.copySpecial(service, CodeBrowserClipboardProvider.LABELS_COMMENTS_TYPE));
	}

	private void pasteToolOne() {

		ClipboardPlugin plugin = getPlugin(toolOne, ClipboardPlugin.class);
		ClipboardContentProviderService service = getClipboardService(plugin);
		DockingActionIf pasteAction = getLocalAction(service, "Paste", plugin);
		assertEnabled(pasteAction, cb.getProvider());
		performAction(pasteAction, true);
		waitForSwing();
	}

	private void setupTool(PluginTool tool) throws Exception {
		tool.addPlugin(ClipboardPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
	}

	private void setupProgramOne() throws Exception {
		// delete all labels and comments over the range 0x31b through 0x0343
		Address min = addr(programOne, 0x31b);
		Address max = addr(programOne, 0x0343);

		int transactionID = programOne.startTransaction("test");
		programOne.getListing().clearComments(min, max);

		SymbolTable st = programOne.getSymbolTable();
		SymbolIterator iter = st.getSymbolIterator(min, true);
		while (iter.hasNext()) {
			Symbol symbol = iter.next();
			if (symbol.getAddress().compareTo(max) > 0) {
				break;
			}
			// cmd puts a dynamic label if there are references
			DeleteLabelCmd cmd = new DeleteLabelCmd(symbol.getAddress(), symbol.getName(),
				symbol.getParentNamespace());
			cmd.applyTo(programOne);
		}
		programOne.endTransaction(transactionID, true);

	}

	private void setupProgramTwo() throws Exception {
		Address min = addr(programTwo, 0x31b);
		Address max = addr(programTwo, 0x0343);
		Listing listing = programTwo.getListing();

		// create a function over the range 0x31b through 0x0343.
		int transactionID = programTwo.startTransaction("test");

		CreateFunctionCmd fnCmd =
			new CreateFunctionCmd(null, min, new AddressSet(min, max), SourceType.ANALYSIS);
		fnCmd.applyTo(programTwo);

		Function function = programTwo.getListing().getFunctionAt(min);

		// add a function comment.
		function.setComment("my function comment");
		// add some Plate, Pre, and Post comments within this function.
		CodeUnit cu = listing.getCodeUnitAt(addr(programTwo, 0x0320));
		cu.setComment(CodeUnit.PLATE_COMMENT, "My Plate Comment");
		cu.setComment(CodeUnit.POST_COMMENT, "My Post comment");

		cu = listing.getCodeUnitAt(addr(programTwo, 0x326));
		cu.setComment(CodeUnit.PLATE_COMMENT, "More Plate Comments (1)");
		cu.setComment(CodeUnit.POST_COMMENT, "More Post comments (1)");
		cu.setComment(CodeUnit.EOL_COMMENT, "More EOL comments (1)");

		cu = listing.getCodeUnitAt(addr(programTwo, 0x32a));
		cu.setComment(CodeUnit.PLATE_COMMENT, "More Plate Comments (2)");
		cu.setComment(CodeUnit.POST_COMMENT, "More Post comments (2)");
		cu.setComment(CodeUnit.EOL_COMMENT, "More EOL comments (2)");

		// Edit the label at 0x32d (RSR05) and make it part of a scope
		Symbol symbol = getUniqueSymbol(programTwo, "RSR05", null);

		assertNotNull(symbol);
		SymbolTable st2 = programTwo.getSymbolTable();
		Namespace ns = st2.createNameSpace(null, "MyNamespace", SourceType.USER_DEFINED);
		symbol.setNamespace(ns);

		programTwo.endTransaction(transactionID, true);
	}

	private void goTo(PluginTool pTool, long offset) {
		Program p = programOne;
		if (pTool == toolTwo) {
			p = programTwo;
		}
		pTool.firePluginEvent(new ProgramLocationPluginEvent("test",
			new AddressFieldLocation(p, addr(p, offset)), p));

		waitForSwing();
	}

	private ClipboardContentProviderService getClipboardService(
			ClipboardPlugin clipboardPlugin) {
		Map<?, ?> serviceMap = (Map<?, ?>) getInstanceField("serviceActionMap", clipboardPlugin);
		Set<?> keySet = serviceMap.keySet();
		for (Object name : keySet) {
			ClipboardContentProviderService service = (ClipboardContentProviderService) name;
			if (service.getClass().equals(CodeBrowserClipboardProvider.class)) {
				return service;
			}
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	private DockingAction getLocalAction(ClipboardContentProviderService service, String actionName,
			ClipboardPlugin clipboardPlugin) {
		Map<?, ?> actionsByService =
			(Map<?, ?>) getInstanceField("serviceActionMap", clipboardPlugin);
		List<DockingAction> actionList = (List<DockingAction>) actionsByService.get(service);
		for (DockingAction pluginAction : actionList) {
			if (pluginAction.getName().equals(actionName)) {
				return pluginAction;
			}
		}

		return null;
	}

	private void assertEnabled(DockingActionIf action, ComponentProvider provider) {
		boolean isEnabled =
			runSwing(() -> {
				return action.isEnabledForContext(provider.getActionContext(null));
			});
		assertTrue("Action was not enabled when it should be", isEnabled);
	}
}
