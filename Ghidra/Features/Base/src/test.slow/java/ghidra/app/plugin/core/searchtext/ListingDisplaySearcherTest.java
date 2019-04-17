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
package ghidra.app.plugin.core.searchtext;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.*;

import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.UserSearchUtils;
import ghidra.util.task.TaskMonitor;

/**
 * Test the searcher that searches fields in the Code Browser
 */
public class ListingDisplaySearcherTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin cb;
	private Program program;
	private ListingDisplaySearcher searcher;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(SearchTextPlugin.class.getName());
		cb = env.getPlugin(CodeBrowserPlugin.class);
		program = buildProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		env.showTool();
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestX86", ProgramBuilder._X86);

		builder.createMemory(".text", Long.toHexString(0x1001000), 0x6600);
		builder.createMemory(".data", Long.toHexString(0x1008000), 0x600);
		builder.createMemory(".rsrc", Long.toHexString(0x100A000), 0x5400);
		builder.createMemory(".bound_import_table", Long.toHexString(0xF0000248), 0xA8);
		builder.createMemory(".debug_data", Long.toHexString(0xF0001300), 0x1C);

		//create and disassemble a function
		builder.setBytes("0x0100415a",
			"55 8b ec 83 ec 0c 33 c0 c7 45 f8 01 00 00 00 21 45 fc 39 45 08 c7 45 f4 04" +
				" 00 00 00 74 1a 8d 45 f4 50 8d 45 f8 50 8d 45 fc 50 6a 00 ff 75 0c ff 75 08 " +
				"ff 15 08 10 00 01 85 c0 75 06 83 7d fc 04 74 05 8b 45 10 eb 03 8b 45 f8 c9 " +
				"c2 0c 00");
		builder.disassemble("0x0100415a", 0x4d, true);
		builder.createFunction("0x0100415a");

		builder.setBytes("0x01002cf5",
			"55 8b ec 83 7d 14 00 56 8b 35 e0 10 00 01 57 74 09 ff 75 14 ff d6 8b f8 " +
				"eb 02 33 ff ff 75 10 ff d6 03 c7 8d 44 00 02 50 6a 40 ff 15 dc 10 00 01 8b " +
				"f0 85 f6 74 27 56 ff 75 14 ff 75 10 e8 5c ff ff ff ff 75 18 ff 75 0c 56 ff 75" +
				" 08 ff 15 04 12 00 01 56 8b f8 ff 15 c0 10 00 01 eb 14 ff 75 18 ff 75 0c ff 75" +
				"10 ff 75 08 ff 15 04 12 00 01 8b f8 8b c7 5f 5e 5d c2 14");
		builder.disassemble("0x01002cf5", 0x121, true);
		builder.createFunction("0x01002cf5");
		builder.createLabel("0x01002cf5", "ghidra");

//		//create and disassemble some code not in a function
		builder.setBytes("0x010029bd", "ff 15 c4 10 00 01 8b d8 33 f6 3b de 74 06");
		builder.disassemble("0x10029bd", 0xe, true);

		builder.createLabel("0x01001068", "CreateDCW");
		builder.createComment("0x01001068", "CreateDCW", CodeUnit.EOL_COMMENT);
		builder.createLabel("0x010010b4", "CreateFileW");
		builder.createLabel("0x010012bc", "CreateWindowExW");

		builder.createEncodedString("0x01001708", "Notepad", StandardCharsets.UTF_16BE, true);
		builder.createEncodedString("0x01001740", "something else", StandardCharsets.UTF_16BE,
			true);

		builder.setBytes("0x01006642", "ff 25 c4 12 00 01");
		builder.disassemble("0x01006642", 0x6, true);
		builder.setBytes("0x01006648", "ff 25 c8 12 00 01");
		builder.disassemble("0x01006648", 0x6, true);

//		StructureDataType dt = new StructureDataType("_person", 0);
//		dt.add(new IntegerDataType(), "id", null);
//		dt.add(new ArrayDataType(new AsciiDataType(), 32, 1), "name", null);
//		dt.add(new BooleanDataType(), "likesCheese", null);
//		dt.add(new PointerDataType(dt), "next", null);

		builder.createComment("0x01006642", "EOL comment", CodeUnit.EOL_COMMENT);
		builder.createComment("0x01006648", "EOL comment", CodeUnit.EOL_COMMENT);

		return builder.getProgram();
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testSingleStepForwardAll() {

		// search all fields in the forward direction
		Address entry = addr(0x0100415a);
		Function func = program.getFunctionManager().getFunctionAt(entry);
		String signature = func.getPrototypeString(false, false);
		ProgramLocation startLoc =
			new FunctionSignatureFieldLocation(program, entry, null, 34, signature);

		// example
		// dword ptr param, EAX
		String searchText = "param";
		SearchOptions options = new SearchOptions(searchText, false, true, false);
		searcher =
			new ListingDisplaySearcher(tool, program, startLoc, null, options, TaskMonitor.DUMMY);

		assertTrue(searcher.hasNext());
		while (searcher.hasNext()) {
			ProgramLocation location = searcher.next();
			testForMatchingText(searchText, location);
		}
	}

	@Test
	public void testSingleStepBackwardsAll() {

		// search all fields in the backward direction
		ProgramLocation startLoc =
			new OperandFieldLocation(program, addr(0x0100415a), null, null, "%bp", 1, 1);

		// example
		// dword ptr param, EAX
		String searchText = "param";
		SearchOptions options = new SearchOptions(searchText, false, false, false);

		searcher =
			new ListingDisplaySearcher(tool, program, startLoc, null, options, TaskMonitor.DUMMY);

		assertTrue(searcher.hasNext());
		while (searcher.hasNext()) {
			ProgramLocation location = searcher.next();
			testForMatchingText(searchText, location);
		}
	}

	@Test
	public void testSearchInstructions() {
		Address entry = addr(0x0100415a);

		Function func = program.getFunctionManager().getFunctionAt(entry);
		String signature = func.getPrototypeString(false, false);
		ProgramLocation startLoc =
			new FunctionSignatureFieldLocation(program, entry, null, 34, signature);

		// example
		// dword ptr param, EAX
		SearchOptions options = new SearchOptions("param", false, false, false, false, true, true,
			false, false, false, true, false, false);
		searcher =
			new ListingDisplaySearcher(tool, program, startLoc, null, options, TaskMonitor.DUMMY);

		//set up list of answers
		ArrayList<Address> startList = new ArrayList<>();
		startList.add(addr(0x0100416c));
		startList.add(addr(0x01004186));
		startList.add(addr(0x01004189));
		startList.add(addr(0x0100419c));

		//check that the text is found there in the correct field
		checkTextFound(startList, OperandFieldLocation.class);
	}

	@Test
	public void testSearchDataForward() {

		ProgramLocation startLoc = new AddressFieldLocation(program, addr(0x01001000));
		SearchOptions options = new SearchOptions("unicode", false, false, false, false, true, true,
			true, true, false, true, false, false);
		searcher =
			new ListingDisplaySearcher(tool, program, startLoc, null, options, TaskMonitor.DUMMY);

		//set up list of answers
		ArrayList<Address> startList = new ArrayList<>();
		startList.add(addr(0x01001708));
		startList.add(addr(0x01001740));

		//check that the text is found there in the correct field
		checkTextFound(startList, MnemonicFieldLocation.class);

	}

	@Test
	public void testSearchDataBackward() {
		ProgramLocation startLoc = new AddressFieldLocation(program, addr(0x01002000));
		//@formatter:off
		SearchOptions options =
			new SearchOptions("unicode", 
				false /*quick*/, 
				false /*functions*/, 
				false /*comments*/, 
				false /*labels*/, 
				true  /*instruction mnemonics*/, 
				true  /*instruction operands*/, 
				true  /*data mnemonics*/, 
				true  /*data operands*/, 
				false /*case sensitive*/,
				false /*is forward*/,
				false /* includeNonLoadedBlocks */,
				false /* search All */);
		//@formatter:on

		searcher =
			new ListingDisplaySearcher(tool, program, startLoc, null, options, TaskMonitor.DUMMY);

		//set up list of answers
		ArrayList<Address> startList = new ArrayList<>();
		startList.add(addr(0x01001740));
		startList.add(addr(0x01001708));

		//check that the text is found there in the correct field
		checkTextFound(startList, MnemonicFieldLocation.class);
	}

	@Test
	public void testStructures() throws Exception {

		showTool(tool);
		Structure struct = new StructureDataType("aStruct", 0);
		DataType floatDt = new FloatDataType();
		DataTypeComponent dtc = struct.add(floatDt);
		dtc = struct.add(floatDt);
		dtc.setComment("this is another float");
		Listing listing = program.getListing();

		int transactionID = program.startTransaction("test");
		try {
			DataType dt = program.getDataTypeManager().addDataType(struct,
				DataTypeConflictHandler.DEFAULT_HANDLER);
			floatDt = program.getDataTypeManager().addDataType(new FloatDataType(),
				DataTypeConflictHandler.DEFAULT_HANDLER);
			listing.createData(addr(0x0100689b), dt);
			listing.createData(addr(0x0100688c), floatDt);
			listing.createData(addr(0x01006890), floatDt);

			Data data = listing.getDataAt(addr(0x0100688c));
			data.setComment(CodeUnit.EOL_COMMENT, "this is a float data type");
			data = listing.getDataAt(addr(0x01006890));
			data.setComment(CodeUnit.EOL_COMMENT, "this is another float data type");

		}
		finally {
			program.endTransaction(transactionID, true);
		}
		// open the structure
		cb.goToField(addr(0x0100689b), "+", 0, 0);
		click(cb, 1);
		waitForPostedSwingRunnables();

		ProgramSelection sel = new ProgramSelection(addr(0x0100688c), addr(0x010068a3));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));

		//search mnemonics and operands
		SearchOptions options = new SearchOptions("float", false /*quick*/, false /*functions*/,
			false /*comments*/, false /*labels*/, true /*instruction mnemonics*/,
			true /*instruction operands*/, true /*data mnemonics*/, true /*data operands*/,
			false /*case sensitive*/, true /*is forward*/, false, false);
		ProgramLocation startLoc = new AddressFieldLocation(program, addr(0x0100688c));
		searcher =
			new ListingDisplaySearcher(tool, program, startLoc, sel, options, TaskMonitor.DUMMY);

		//set up list of answers
		ArrayList<Address> startList = new ArrayList<>();
		startList.add(addr(0x0100688c));
		startList.add(addr(0x01006890));
		startList.add(addr(0x0100689b));
		startList.add(addr(0x0100689f));

		//check that the text is found there in the correct field
		checkTextFound(startList, MnemonicFieldLocation.class);

		//now search comments
		options = new SearchOptions("float", false /*quick*/, false /*functions*/,
			true /*comments*/, false /*labels*/, false /*instruction mnemonics*/,
			false /*instruction operands*/, false /*data mnemonics*/, false /*data operands*/,
			false /*case sensitive*/, true /*is forward*/, false, false);
		startLoc = new AddressFieldLocation(program, addr(0x0100688c));
		searcher =
			new ListingDisplaySearcher(tool, program, startLoc, sel, options, TaskMonitor.DUMMY);

		//remove the one without a comment

		ArrayList<Address> startList2 = new ArrayList<>();
		startList2.add(addr(0x0100688c));
		startList2.add(addr(0x01006890));
		startList2.add(addr(0x0100689f));

		//check that the text is found there in the correct field
		checkTextFound(startList2, EolCommentFieldLocation.class); //waiting for Bill to fix the search
	}

	@Test
	public void testStructures2() throws Exception {

		showTool(tool);
		Structure struct = new StructureDataType("aStruct", 0);
		DataType floatDt = new FloatDataType();
		DataTypeComponent dtc = struct.add(floatDt);
		dtc = struct.add(floatDt);
		dtc.setComment("this is another float");
		Listing listing = program.getListing();

		int transactionID = program.startTransaction("test");
		try {
			DataType dt = program.getDataTypeManager().addDataType(struct,
				DataTypeConflictHandler.DEFAULT_HANDLER);
			floatDt = program.getDataTypeManager().addDataType(new FloatDataType(),
				DataTypeConflictHandler.DEFAULT_HANDLER);
			listing.createData(addr(0x0100689b), dt);
			listing.createData(addr(0x0100688c), floatDt);
			listing.createData(addr(0x01006890), floatDt);

			Data data = listing.getDataAt(addr(0x0100688c));
			data.setComment(CodeUnit.EOL_COMMENT, "this is a float data type");
			data = listing.getDataAt(addr(0x01006890));
			data.setComment(CodeUnit.EOL_COMMENT, "this is another float data type");

		}
		finally {
			program.endTransaction(transactionID, true);
		}
		program.flushEvents();
		waitForPostedSwingRunnables();

		// open the structure
		cb.goToField(addr(0x0100689b), "+", 0, 0);
		click(cb, 1);
		waitForPostedSwingRunnables();

		ProgramSelection sel = new ProgramSelection(addr(0x0100688c), addr(0x0100689f));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));
		SearchOptions options = new SearchOptions("float", false, true, false); // all fields

		ProgramLocation startLoc = new EolCommentFieldLocation(program, addr(0x0100688c), null,
			new String[] { "this is a float data type" }, 0, 3, 0);
		searcher =
			new ListingDisplaySearcher(tool, program, startLoc, sel, options, TaskMonitor.DUMMY);

		ProgramLocation loc = searcher.next();
		assertNotNull(loc);
		assertEquals(addr(0x0100688c), loc.getByteAddress());
		assertTrue(loc instanceof CommentFieldLocation);
		//
		loc = searcher.next();
		assertNotNull(loc);
		assertEquals(addr(0x01006890), loc.getByteAddress());
		assertTrue(loc instanceof MnemonicFieldLocation);
		MnemonicFieldLocation mloc = (MnemonicFieldLocation) loc;
		assertEquals("float", mloc.getMnemonic());
		//
		loc = searcher.next();
		assertNotNull(loc);
		assertEquals(addr(0x01006890), loc.getByteAddress());
		assertTrue(loc instanceof CommentFieldLocation);
		//
		loc = searcher.next();
		assertNotNull(loc);
		assertEquals(addr(0x0100689b), loc.getByteAddress());
		assertTrue(loc instanceof MnemonicFieldLocation);
		mloc = (MnemonicFieldLocation) loc;
		assertEquals("float", mloc.getMnemonic());
		//
		loc = searcher.next();
		assertNotNull(loc);
		assertEquals(addr(0x0100689f), loc.getByteAddress());
		assertTrue(loc instanceof MnemonicFieldLocation);
		mloc = (MnemonicFieldLocation) loc;
		assertEquals("float", mloc.getMnemonic());
		//
		loc = searcher.next();
		assertNotNull(loc);
		assertEquals(addr(0x0100689f), loc.getByteAddress());
		assertTrue(loc instanceof CommentFieldLocation);

		assertTrue(!searcher.hasNext());
		assertNull(searcher.next());
	}

	@Test
	public void testStructuresAddrSet() throws Exception {

		// search interior of structure within a selection
		showTool(tool);
		Structure struct = new StructureDataType("aStruct", 0);
		DataType floatDt = new FloatDataType();
		DataTypeComponent dtc = struct.add(floatDt);
		dtc = struct.add(floatDt);
		dtc.setComment("this is another float");
		Listing listing = program.getListing();

		int transactionID = program.startTransaction("test");
		try {
			DataType dt = program.getDataTypeManager().addDataType(struct,
				DataTypeConflictHandler.DEFAULT_HANDLER);
			floatDt = program.getDataTypeManager().addDataType(new FloatDataType(),
				DataTypeConflictHandler.DEFAULT_HANDLER);
			listing.createData(addr(0x0100689b), dt);
			listing.createData(addr(0x0100688c), floatDt);
			listing.createData(addr(0x01006890), floatDt);

			Data data = listing.getDataAt(addr(0x0100688c));
			data.setComment(CodeUnit.EOL_COMMENT, "this is a float data type");
			data = listing.getDataAt(addr(0x01006890));
			data.setComment(CodeUnit.EOL_COMMENT, "this is another float data type");

		}
		finally {
			program.endTransaction(transactionID, true);
		}
		program.flushEvents();
		waitForPostedSwingRunnables();

		// open the structure
		cb.goToField(addr(0x0100689b), "+", 0, 0);
		click(cb, 1);
		waitForPostedSwingRunnables();

		AddressSet set = new AddressSet();
		set.addRange(addr(0x0100688c), addr(0x0100688f));
		set.addRange(addr(0x0100689b), addr(0x010068a2));
		ProgramSelection sel = new ProgramSelection(set);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));
		SearchOptions options = new SearchOptions("float", false, true, false); // all fields

		ProgramLocation startLoc = new EolCommentFieldLocation(program, addr(0x0100688c), null,
			new String[] { "this is a float data type" }, 0, 3, 0);
		searcher =
			new ListingDisplaySearcher(tool, program, startLoc, sel, options, TaskMonitor.DUMMY);

		ProgramLocation loc = searcher.next();
		assertNotNull(loc);
		assertEquals(addr(0x0100688c), loc.getByteAddress());
		assertTrue(loc instanceof CommentFieldLocation);
		//
		loc = searcher.next();
		assertNotNull(loc);
		assertEquals(addr(0x0100689b), loc.getByteAddress());
		assertTrue(loc instanceof MnemonicFieldLocation);
		MnemonicFieldLocation mloc = (MnemonicFieldLocation) loc;
		assertEquals("float", mloc.getMnemonic());
		//
		loc = searcher.next();
		assertNotNull(loc);
		assertEquals(addr(0x0100689f), loc.getByteAddress());
		assertTrue(loc instanceof MnemonicFieldLocation);
		mloc = (MnemonicFieldLocation) loc;
		assertEquals("float", mloc.getMnemonic());
		//
		loc = searcher.next();
		assertNotNull(loc);
		assertEquals(addr(0x0100689f), loc.getByteAddress());
		assertTrue(loc instanceof CommentFieldLocation);

		assertTrue(!searcher.hasNext());
		assertNull(searcher.next());
	}

	@Test
	public void testLabels() {
		ProgramLocation startLoc = new AddressFieldLocation(program, addr(0x01001000));
		String searchText = "Create";
		//@formatter:off
		SearchOptions options =
			new SearchOptions(searchText, 
				false /*quick*/, 
				false /*functions*/, 
				false /*comments*/, 
				true  /*labels*/, 
				false /*instruction mnemonics*/, 
				false /*instruction operands*/, 
				false /*data mnemonics*/, 
				false /*data operands*/, 
				false /*case sensitive*/,
				true  /*is forward*/,
				false /* includeNonLoadedBlocks */,
				false /* searchAll */
				);
		//@formatter:on

		searcher = new ListingDisplaySearcher(tool, program, startLoc, null /*no address set*/,
			options, TaskMonitor.DUMMY);

		//set up list of answers
		ArrayList<Address> startList = new ArrayList<>();

		startList.add(addr(0x01001068));
		startList.add(addr(0x010010b4));
		startList.add(addr(0x010012bc));

		//check that the text is found there in the correct field
		checkTextFound(startList, LabelFieldLocation.class);
	}

	@Test
	public void testLabelsWithSelection() {
		AddressSet as = new AddressSet();
		as.add(addr(0x1001000), addr(0x1001100)); // this range contains all labels we expect to find
		ProgramLocation startLoc = new AddressFieldLocation(program, addr(0x01001000));
		String searchText = "Create";
		//@formatter:off
		SearchOptions options =
			new SearchOptions(searchText, 
				false /*quick*/, 
				false /*functions*/, 
				false /*comments*/, 
				true  /*labels*/, 
				false /*instruction mnemonics*/, 
				false /*instruction operands*/, 
				false /*data mnemonics*/, 
				false /*data operands*/, 
				false /*case sensitive*/,
				true  /*is forward*/,
				false /* includeNonLoadedBlocks */,
				false /* searchAll */
				);
		//@formatter:on

		searcher =
			new ListingDisplaySearcher(tool, program, startLoc, as, options, TaskMonitor.DUMMY);

		//set up list of answers
		ArrayList<Address> startList = new ArrayList<>();

		startList.add(addr(0x01001068));
		startList.add(addr(0x010010b4));

		//check that the text is found there in the correct field
		checkTextFound(startList, LabelFieldLocation.class);
	}

	@Test
	public void testFunctions() {
		doTestFunctions(null /* no address set */);
	}

	@Test
	public void testFunctionsWithSelection() {
		AddressSet as = new AddressSet();
		as.addRange(addr(0x1002cf0), addr(0x1004fb5)); // bigger range than the function, just for fun
		doTestFunctions(as);
	}

	private void doTestFunctions(AddressSetView as) {
		ProgramLocation startLoc = new AddressFieldLocation(program, addr(0x01001000));
		String searchText = "ghidra";
		//@formatter:off
		SearchOptions options =
			new SearchOptions(searchText, 
				false /*quick*/, 
				true  /*functions*/, 
				false /*comments*/, 
				false /*labels*/, 
				false /*instruction mnemonics*/, 
				false /*instruction operands*/, 
				false /*data mnemonics*/, 
				false /*data operands*/, 
				false /*case sensitive*/,
				true  /*is forward*/,
				false /* includeNonLoadedBlocks */,
				false /* searchAll */
				);
		//@formatter:on

		searcher =
			new ListingDisplaySearcher(tool, program, startLoc, as, options, TaskMonitor.DUMMY);

		//set up list of answers
		ArrayList<Address> startList = new ArrayList<>();

		startList.add(addr(0x01002cf5));

		//check that the text is found there in the correct field
		checkTextFound(startList, FunctionNameFieldLocation.class);
	}

	@Test
	public void testComments() {
		doTestComments(null /* no address set */, 2);
	}

	@Test
	public void testCommentsWithSelection() {
		AddressSet as = new AddressSet();
		as.add(addr(0x1001010), addr(0x1007000)); // arbitrary, restrictive range
		doTestComments(as, 2);
	}

	private void doTestComments(AddressSetView as, int matchCount) {
		ProgramLocation startLoc = new AddressFieldLocation(program, addr(0x01001000));
		String searchText = "EOL comment";
		//@formatter:off
		SearchOptions options =
			new SearchOptions(searchText, 
				false /*quick*/, 
				false /*functions*/, 
				true  /*comments*/, 
				false /*labels*/, 
				false /*instruction mnemonics*/, 
				false /*instruction operands*/, 
				false /*data mnemonics*/, 
				false /*data operands*/, 
				false /*case sensitive*/,
				true  /*is forward*/,
				false /* includeNonLoadedBlocks */,
				false /* searchAll */
				);
		//@formatter:on

		searcher =
			new ListingDisplaySearcher(tool, program, startLoc, null, options, TaskMonitor.DUMMY);

		//set up list of answers
		ArrayList<Address> startList = new ArrayList<>();

		startList.add(addr(0x01006642));
		startList.add(addr(0x01006648));

		//check that the text is found there in the correct field
		checkTextFound(startList, EolCommentFieldLocation.class);
	}

	@Test
	public void testMultipleMatchesAtSameAddress() {

		// one address in this range contains an instruction with multiple matches for that address
		AddressSet as = new AddressSet();
		as.add(addr(0x1001000), addr(0x1001100));

		ProgramLocation startLoc = new AddressFieldLocation(program, addr(0x01001000));
		SearchOptions searchAllOptions = new SearchOptions("CreateDCW",
			false /* not case sensitive */, true /*forward*/, false /*includeNonLoadedBlocks*/);

		searcher = new ListingDisplaySearcher(tool, program, startLoc, as, searchAllOptions,
			TaskMonitor.DUMMY);

		assertTrue(searcher.hasNext());

		ProgramLocation loc = searcher.next();
		assertNotNull(loc);
		assertEquals(addr(0x01001068), loc.getByteAddress());
		assertTrue(loc instanceof LabelFieldLocation);
		loc = searcher.next();
		assertNotNull(loc);
		assertEquals(addr(0x01001068), loc.getByteAddress());
		assertTrue(loc instanceof EolCommentFieldLocation);
		loc = searcher.next();
		assertNull(loc);

	}

	@Test
	public void testRangeWithAddressInsideOfThatRange() {
		//
		// Set up a range that contains multiple matches.    Put the start address past one 
		// of the addresses and make sure that match is not found.
		// 
		AddressSet as = new AddressSet();
		as.add(addr(0x100415a), addr(0x10041a5));

		ProgramLocation startLoc = new AddressFieldLocation(program, addr(0x1004178));
		//@formatter:off
		SearchOptions options =
			new SearchOptions("LAB", 
				false /*quick*/, 
				false /*functions*/, 
				false /*comments*/, 
				true  /*labels*/, 
				true  /*instruction mnemonics*/, 
				true  /*instruction operands*/, 
				false /*data mnemonics*/, 
				false /*data operands*/, 
				false /*case sensitive*/,
				true  /*is forward*/,
				false /* includeNonLoadedBlocks */,
				false /* searchAll */
				);
		//@formatter:on

		searcher =
			new ListingDisplaySearcher(tool, program, startLoc, as, options, TaskMonitor.DUMMY);

		// originally had 8 matches, but since we moved the start address past the start of the
		// range, we now only have 7
		//check that the text is found there in the correct field
		checkTextFound(addr(0x01004192), LabelFieldLocation.class);
		checkTextFound(addr(0x01004194), OperandFieldLocation.class);
		checkTextFound(addr(0x0100419a), OperandFieldLocation.class);
		checkTextFound(addr(0x0100419c), LabelFieldLocation.class);
		checkTextFound(addr(0x0100419f), OperandFieldLocation.class);
		checkTextFound(addr(0x010041a1), LabelFieldLocation.class);
		checkTextFound(addr(0x010041a4), LabelFieldLocation.class);
	}

	// this variant exposed a bug only present during 'search all fields' operations
	@Test
	public void testRangeWithAddressInsideOfThatRange_SearchAll() {
		//
		// Set up a range that contains multiple matches.    Put the start address past one 
		// of the addresses and make sure that match is not found.
		// 
		AddressSet as = new AddressSet();
		as.add(addr(0x100415a), addr(0x10041a5));

		ProgramLocation startLoc = new AddressFieldLocation(program, addr(0x1004178));
		SearchOptions options = new SearchOptions("LAB", false, true, false);

		searcher =
			new ListingDisplaySearcher(tool, program, startLoc, as, options, TaskMonitor.DUMMY);

		// originally had 8 matches, but since we moved the start address past the start of the
		// range, we now only have 7
		//check that the text is found there in the correct field
		checkTextFound(addr(0x01004192), LabelFieldLocation.class);
		checkTextFound(addr(0x01004194), OperandFieldLocation.class);
		checkTextFound(addr(0x0100419a), OperandFieldLocation.class);
		checkTextFound(addr(0x0100419c), LabelFieldLocation.class);
		checkTextFound(addr(0x0100419f), OperandFieldLocation.class);
		checkTextFound(addr(0x010041a1), LabelFieldLocation.class);
		checkTextFound(addr(0x010041a4), LabelFieldLocation.class);

	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void testForMatchingText(String text, ProgramLocation location) {

		assertNotNull(location);

		if (location instanceof FunctionSignatureFieldLocation) {
			FunctionSignatureFieldLocation fLoc = ((FunctionSignatureFieldLocation) location);
			Pattern regexp = UserSearchUtils.createSearchPattern(text, false);
			Matcher matcher = regexp.matcher(fLoc.getSignature());
			assertTrue(matcher.find());
		}
		else if (location instanceof VariableNameFieldLocation) {
			VariableNameFieldLocation vLoc = (VariableNameFieldLocation) location;
			assertTrue(vLoc.getName().indexOf(text) >= 0);
			assertEquals(0, vLoc.getCharOffset());
		}
		else if (location instanceof OperandFieldLocation) {
			OperandFieldLocation opLoc = ((OperandFieldLocation) location);
			assertTrue(opLoc.getOperandRepresentation().indexOf(text) >= 0);
		}
		else if (location instanceof EolCommentFieldLocation) {
			EolCommentFieldLocation eLoc = (EolCommentFieldLocation) location;
			assertEquals(CodeUnit.EOL_COMMENT, eLoc.getCommentType());
			String[] comment = eLoc.getComment();
			for (String element : comment) {
				if (element.indexOf(text) >= 0) {
					return;
				}
			}
			Assert.fail(
				"Did not find matching text in the EOL comment at address " + eLoc.getAddress());
		}
		else if (location instanceof AutomaticCommentFieldLocation) {
			AutomaticCommentFieldLocation eLoc = (AutomaticCommentFieldLocation) location;
			assertEquals(CodeUnit.EOL_COMMENT, eLoc.getCommentType());
			String[] comment = eLoc.getComment();
			for (String element : comment) {
				if (element.indexOf(text) >= 0) {
					return;
				}
			}
			Assert.fail("Did not find matching text in the automatic comment at address " +
				eLoc.getAddress());
		}
		else {
			Assert.fail("Unexpected ProgramLocation type: " + location);
		}
	}

	private void checkTextFound(ArrayList<Address> startList, Class<?> fieldClass) {

		for (int i = 0; i < startList.size(); i++) {
			ProgramLocation loc = searcher.next();
			assertNotNull(loc);
			Address start = startList.get(i);

			assertTrue(fieldClass.isAssignableFrom(loc.getClass()));
			assertEquals(start, loc.getAddress());
		}

		assertTrue(!searcher.hasNext());
	}

	private void checkTextFound(Address addr, Class<?> fieldClass) {
		ProgramLocation loc;

		loc = searcher.next();
		assertNotNull(loc);

		assertTrue(fieldClass.isAssignableFrom(loc.getClass()));
		assertEquals(addr, loc.getAddress());
	}

	private Address addr(long address) {
		return program.getMinAddress().getNewAddress(address);
	}

}
