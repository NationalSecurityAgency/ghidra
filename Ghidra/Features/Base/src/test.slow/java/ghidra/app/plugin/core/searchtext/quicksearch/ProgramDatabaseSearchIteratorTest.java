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
package ghidra.app.plugin.core.searchtext.quicksearch;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.regex.Pattern;

import org.junit.*;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.plugin.core.searchtext.SearchOptions;
import ghidra.app.plugin.core.searchtext.Searcher;
import ghidra.app.plugin.core.searchtext.databasesearcher.*;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.CodeUnitFormatOptions.ShowBlockName;
import ghidra.program.model.listing.CodeUnitFormatOptions.ShowNamespace;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.test.*;
import ghidra.util.UserSearchUtils;
import ghidra.util.task.TaskMonitor;
import junit.framework.TestCase;

public class ProgramDatabaseSearchIteratorTest extends AbstractGhidraHeadedIntegrationTest {

	private Program program;
	private AddressSpace space;
	private TestEnv env;
	private PluginTool tool;
	private Address currentAddress;
	private ToyProgramBuilder builder;
	private TaskMonitor monitor = TaskMonitor.DUMMY;

	public ProgramDatabaseSearchIteratorTest() {
		super();
	}

	private void createIMM(long address) throws MemoryAccessException {
		builder.addBytesMoveImmediate(address, (short) 5);
		builder.disassemble(Long.toHexString(address), 2);
	}

	private void createFallThru(long address) throws MemoryAccessException {
		builder.addBytesFallthrough(address);
		builder.disassemble(Long.toHexString(address), 2);
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		builder = new ToyProgramBuilder("Test", false);
		program = builder.getProgram();
		builder.createMemory(".text", "0x1001000", 0x1000);
		builder.createMemory(".text", "0x1005000", 0x1000);
		builder.createMemory(".dummy", "0", 100);

		createFallThru(0x1001010);
		createIMM(0x1001100);
		createFallThru(0x1001150);
		createIMM(0x1001200);
		createFallThru(0x1005f00);
		createIMM(0x1005f3e);
		createFallThru(0x1005f50);
		createIMM(0x1005f41);
		createFallThru(0x1005ff0);
//		LAB_010018b3
		createIMM(0x10018b3);
		builder.createMemoryReference("0x1005f41", "0x10018b3", RefType.COMPUTED_JUMP,
			SourceType.ANALYSIS);

		Parameter p1 = new ParameterImpl(null, new DWordDataType(), program);
		Parameter p2 = new ParameterImpl(null, new DWordDataType(), program);
		p2.setComment("cause a hit! -- imm xxx");
		Parameter p3 = new ParameterImpl(null, new DoubleDataType(), program);
		builder.createEmptyFunction("MyFunc", "0", 26, new WordDataType(), p1, p2, p3);
		builder.createComment("0", "Blah Blah Blah -- imm", CodeUnit.PLATE_COMMENT);

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		space = program.getMinAddress().getAddressSpace();
		env.showTool();
	}

	/**
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		env.dispose();
		program = null;
		space = null;
	}

	private ProgramLocation getNextMatch(ProgramDatabaseFieldSearcher searcher) {

		while (currentAddress != null) {
			if (searcher.hasMatch(currentAddress)) {
				return searcher.getMatch();
			}
			currentAddress = searcher.getNextSignificantAddress(currentAddress);
		}
		return null;
	}

	@Test
	public void testEOLCommentIterator() {

		Pattern pattern = UserSearchUtils.createSearchPattern("XXZ*", false);
		ProgramLocation startLocation = new ProgramLocation(program, program.getMinAddress());
		CommentFieldSearcher searcher = new CommentFieldSearcher(program, startLocation, null, true,
			pattern, CodeUnit.EOL_COMMENT);
		currentAddress = searcher.getNextSignificantAddress(null);
		assertNull(getNextMatch(searcher));

		// add a comment with no match
		addEolComment(0x1005146L, "Test EOL comments...");
		searcher = new CommentFieldSearcher(program, startLocation, null, true, pattern,
			CodeUnit.EOL_COMMENT);
		currentAddress = searcher.getNextSignificantAddress(null);
		assertNull(getNextMatch(searcher));

		// add a comment that has one match
		addEolComment(0x1005d4bL, "Test something with eXXZabc");
		searcher = new CommentFieldSearcher(program, startLocation, null, true, pattern,
			CodeUnit.EOL_COMMENT);
		currentAddress = searcher.getNextSignificantAddress(null);
		ProgramLocation loc = getNextMatch(searcher);
		assertNotNull(loc);
		assertEquals(getAddr(0x1005d4bL), loc.getAddress());

		// add a comment with two matches for a total of 3 matches
		addEolComment(0x100595f, "Hit found: eXXZabc followed by XXZabc");
		searcher = new CommentFieldSearcher(program, startLocation, null, true, pattern,
			CodeUnit.EOL_COMMENT);
		currentAddress = searcher.getNextSignificantAddress(null);

		loc = getNextMatch(searcher);

		assertNotNull(loc);
		assertEquals(getAddr(0x100595f), loc.getAddress());
		loc = getNextMatch(searcher);
		System.out.println(loc);
		assertEquals(getAddr(0x100595f), loc.getAddress());
		loc = getNextMatch(searcher);
		assertNotNull(loc);
		loc = getNextMatch(searcher);
		assertNull(loc);

	}

	@Test
	public void testSingleWildcard() {
		addEolComment(0x100101cL, "Test EOL comments...");
		addEolComment(0x100101dL, "Test something with eXXZabc");
		addEolComment(0x100101fL, "Hit found: eXXZabc followed by XXZabc");

		Pattern pattern = UserSearchUtils.createSearchPattern("*", false);
		ProgramLocation startLocation = new ProgramLocation(program, program.getMinAddress());
		CommentFieldSearcher searcher = new CommentFieldSearcher(program, startLocation, null, true,
			pattern, CodeUnit.EOL_COMMENT);
		currentAddress = searcher.getNextSignificantAddress(null);
		int count = 0;
		Address[] addrs =
			new Address[] { getAddr(0x100101cL), getAddr(0x100101dL), getAddr(0x100101fL) };

		ProgramLocation loc = null;
		while ((loc = getNextMatch(searcher)) != null) {
			assertEquals(addrs[count], loc.getAddress());
			++count;
		}
	}

	@Test
	public void testWildcardInMiddle() {
		addEolComment(0x100101cL, "Test EOL comments...");
		addEolComment(0x100101dL, "Test something with ABCeXXZ123");
		addEolComment(0x100101fL, "Hit found: ABCxyzvvXXZ123 followed by ABCxqa123");

		Pattern pattern = UserSearchUtils.createSearchPattern("ABC*123", false);
		ProgramLocation startLocation = new ProgramLocation(program, program.getMinAddress());
		CommentFieldSearcher searcher = new CommentFieldSearcher(program, startLocation, null, true,
			pattern, CodeUnit.EOL_COMMENT);
		currentAddress = searcher.getNextSignificantAddress(null);

		ProgramLocation loc = getNextMatch(searcher);
		assertNotNull(loc);
		assertEquals(getAddr(0x100101dL), loc.getAddress());

		loc = getNextMatch(searcher);
		assertEquals(getAddr(0x100101fL), loc.getAddress());

		loc = getNextMatch(searcher);
		assertEquals(getAddr(0x100101fL), loc.getAddress());

		assertNull(getNextMatch(searcher));

	}

	@Test
	public void testMnemonicOperandIteratorNoMatch() {

		Pattern pattern = UserSearchUtils.createSearchPattern("immxx", false);
		ProgramLocation startLocation = new ProgramLocation(program, program.getMinAddress());
		CodeUnitFormat format = new CodeUnitFormat(ShowBlockName.NEVER, ShowNamespace.NEVER);
		ProgramDatabaseFieldSearcher searcher =
			InstructionMnemonicOperandFieldSearcher.createInstructionMnemonicAndOperandFieldSearcher(
				program, startLocation, null, true, pattern, format);
		currentAddress = searcher.getNextSignificantAddress(null);

		assertNull(getNextMatch(searcher));

	}

	@Test
	public void testMnemonicOperandIterator() {

		Pattern pattern = UserSearchUtils.createSearchPattern("imm", true);
		ProgramLocation startLocation = new ProgramLocation(program, program.getMinAddress());
		ProgramDatabaseFieldSearcher searcher =
			InstructionMnemonicOperandFieldSearcher.createInstructionMnemonicAndOperandFieldSearcher(
				program, startLocation, null, true, pattern, CodeUnitFormat.DEFAULT);
		currentAddress = searcher.getNextSignificantAddress(null);

		ProgramLocation nextMatch = getNextMatch(searcher);
		assertNotNull(nextMatch);

		startLocation = new ProgramLocation(program, getAddr(0x1001000));
		searcher =
			InstructionMnemonicOperandFieldSearcher.createInstructionMnemonicAndOperandFieldSearcher(
				program, startLocation, null, true, pattern, CodeUnitFormat.DEFAULT);
		currentAddress = searcher.getNextSignificantAddress(null);

		nextMatch = getNextMatch(searcher);
		assertNotNull(nextMatch);

		assertTrue("Expected MnemonicFieldLocation, got " + nextMatch.getClass() + " instead!",
			(nextMatch instanceof MnemonicFieldLocation));

		nextMatch = getNextMatch(searcher);
		assertNotNull(nextMatch);// 0x6425L

		assertTrue("Expected MnemonicFieldLocation, got " + nextMatch.getClass() + " instead!",
			(nextMatch instanceof MnemonicFieldLocation));

		// now start iterating backwards

		pattern = UserSearchUtils.createSearchPattern("imm", false);
		startLocation = new ProgramLocation(program, getAddr(0x1005f53));
		searcher =
			InstructionMnemonicOperandFieldSearcher.createInstructionMnemonicAndOperandFieldSearcher(
				program, startLocation, null, false, pattern, CodeUnitFormat.DEFAULT);
		currentAddress = searcher.getNextSignificantAddress(null);

		nextMatch = getNextMatch(searcher);
		assertNotNull(nextMatch);
		assertEquals(getAddr(0x1005f41), nextMatch.getAddress());

		startLocation = new MnemonicFieldLocation(program,
			program.getMinAddress().getNewAddress(0x1005f53), null, null, "imm", 2);
		searcher =
			InstructionMnemonicOperandFieldSearcher.createInstructionMnemonicAndOperandFieldSearcher(
				program, startLocation, null, false, pattern, CodeUnitFormat.DEFAULT);
		currentAddress = searcher.getNextSignificantAddress(null);

		nextMatch = getNextMatch(searcher);
		assertNotNull(nextMatch);

		assertEquals(getAddr(0x1005f41), nextMatch.getAddress());

		nextMatch = getNextMatch(searcher);
		assertNotNull(nextMatch);
		assertEquals(getAddr(0x1005f3e), nextMatch.getAddress());
	}

	@Test
	public void testLabelMatcherIterator() throws Exception {
		addLabel(0x10018b5, "aLABel");

		Pattern pattern = UserSearchUtils.createSearchPattern("LAB", true);
		ProgramLocation startLocation = new ProgramLocation(program, getAddr(0x1001000));
		ProgramDatabaseFieldSearcher searcher =
			new LabelFieldSearcher(program, startLocation, null, true, pattern);
		currentAddress = searcher.getNextSignificantAddress(null);

		ProgramLocation nextMatch = getNextMatch(searcher);
		assertNotNull(nextMatch);
		assertTrue(nextMatch instanceof LabelFieldLocation);
		LabelFieldLocation labelLocation = (LabelFieldLocation) nextMatch;
		assertEquals("LAB_010018b3", labelLocation.getName());
		nextMatch = getNextMatch(searcher);
		assertNotNull(nextMatch);
		assertTrue(nextMatch instanceof LabelFieldLocation);
		labelLocation = (LabelFieldLocation) nextMatch;
		assertEquals("aLABel", labelLocation.getName());
	}

	@Test
	public void testLabelMatcherIterator2() throws Exception {
		SymbolTable st = program.getSymbolTable();
		int transactionID = program.startTransaction("Test");
		try {
			st.createLabel(getAddr(0x1001950), "LaLaLABel", SourceType.USER_DEFINED);
			st.createLabel(getAddr(0x1001954), "aLABel", SourceType.USER_DEFINED);
			st.createLabel(getAddr(0x1001960), "zzzLABbbbb", SourceType.USER_DEFINED);
			st.createLabel(getAddr(0x1001960), "aaaaLAB123", SourceType.USER_DEFINED);
			st.createLabel(getAddr(0x1001960), "NotAMatch", SourceType.USER_DEFINED);
			st.createLabel(getAddr(0x1001960), "NotAMatchEither", SourceType.USER_DEFINED);
			st.createLabel(getAddr(0x1001960), "myLABEL", SourceType.USER_DEFINED);

		}
		finally {
			program.endTransaction(transactionID, true);
		}

		Pattern pattern = UserSearchUtils.createSearchPattern("LAB", true);
		ProgramLocation startLocation = new ProgramLocation(program, getAddr(0x1001950));
		ProgramDatabaseFieldSearcher searcher =
			new LabelFieldSearcher(program, startLocation, null, true, pattern);
		currentAddress = searcher.getNextSignificantAddress(null);

		ProgramLocation nextMatch = getNextMatch(searcher);
		assertNotNull(nextMatch);
		assertTrue(nextMatch instanceof LabelFieldLocation);
		LabelFieldLocation floc = (LabelFieldLocation) nextMatch;
		assertEquals("LaLaLABel", floc.getName());

		nextMatch = getNextMatch(searcher);
		assertNotNull(nextMatch);
		assertTrue(nextMatch instanceof LabelFieldLocation);
		floc = (LabelFieldLocation) nextMatch;
		assertEquals("aLABel", floc.getName());
		assertEquals(getAddr(0x1001954), floc.getAddress());

		nextMatch = getNextMatch(searcher);
		assertNotNull(nextMatch);
		assertTrue(nextMatch instanceof LabelFieldLocation);
		floc = (LabelFieldLocation) nextMatch;
		assertNotNull(floc);
		assertEquals("aaaaLAB123", floc.getName());
		assertEquals(getAddr(0x1001960), floc.getAddress());

		nextMatch = getNextMatch(searcher);
		assertNotNull(nextMatch);
		assertTrue(nextMatch instanceof LabelFieldLocation);
		floc = (LabelFieldLocation) nextMatch;
		assertNotNull(floc);
		assertEquals("myLABEL", floc.getName());
		assertEquals(getAddr(0x1001960), floc.getAddress());

		nextMatch = getNextMatch(searcher);
		assertNotNull(nextMatch);
		assertTrue(nextMatch instanceof LabelFieldLocation);
		floc = (LabelFieldLocation) nextMatch;
		assertEquals("zzzLABbbbb", floc.getName());
		assertEquals(getAddr(0x1001960), floc.getAddress());

		nextMatch = getNextMatch(searcher);
		if (nextMatch != null) {
			floc = (LabelFieldLocation) nextMatch;
			assertTrue(floc.getAddress().compareTo(getAddr(0x1001960)) > 0);
		}
	}

	void addEolComment(long longAddr, String comment) {
		SetCommentCmd cmd = new SetCommentCmd(getAddr(longAddr), CodeUnit.EOL_COMMENT, comment);
		tool.execute(cmd, program);
	}

	void addPreComment(long longAddr, String comment) {
		SetCommentCmd cmd = new SetCommentCmd(getAddr(longAddr), CodeUnit.PRE_COMMENT, comment);
		tool.execute(cmd, program);
	}

	void addPostComment(long longAddr, String comment) {
		SetCommentCmd cmd = new SetCommentCmd(getAddr(longAddr), CodeUnit.POST_COMMENT, comment);
		tool.execute(cmd, program);
	}

	void addLabel(long longAddr, String name) {
		AddLabelCmd cmd = new AddLabelCmd(getAddr(longAddr), name, SourceType.USER_DEFINED);
		tool.execute(cmd, program);
	}

	@Test
	public void testTextSearcher() throws Exception {
		addEolComment(0x1001955L, "EOL: PUSH Hit");
		addLabel(0x1001960L, "LabPUSHHit");
		addPreComment(0x1001960L, "PreComment: PUSH Hit");
		addPostComment(0x1001960L, "Post: PUSH hit");

		// Search for 
		SearchOptions options = new SearchOptions("PUSH", true, true, true, true, true, true, true,
			true, true, true, false, false);
		ProgramLocation startLoc = new ProgramLocation(program, getAddr(0x1001950));
		Searcher ts = new ProgramDatabaseSearcher(tool, program, startLoc, null, options, monitor);

		ProgramLocation loc = ts.search();
		assertNotNull(loc);

		assertTrue("Expected CommentFieldLocation, got " + loc.getClass() + " instead!",
			(loc instanceof CommentFieldLocation));
		CommentFieldLocation cloc = (CommentFieldLocation) loc;
		assertEquals(cloc.getCharOffset(), 5);

		// should be 3 hits at address 0x1001960
		loc = ts.search();
		assertNotNull(loc);
		assertTrue("Expected CommentFieldLocation, got " + loc.getClass() + " instead!",
			(loc instanceof CommentFieldLocation));

		assertEquals(getAddr(0x1001960L), loc.getAddress());
		cloc = (CommentFieldLocation) loc;
		assertEquals(cloc.getCharOffset(), 12);

		loc = ts.search();
		assertNotNull(loc);
		assertTrue("Expected LabelFieldLocation, got " + loc.getClass() + " instead!",
			(loc instanceof LabelFieldLocation));
		LabelFieldLocation floc = (LabelFieldLocation) loc;
		assertEquals(floc.getCharOffset(), 3);
		assertEquals(getAddr(0x1001960L), floc.getAddress());

		loc = ts.search();
		assertEquals(getAddr(0x1001960), loc.getAddress());
		assertTrue("Expected CommentFieldLocation, got " + loc.getClass() + " instead!",
			(loc instanceof CommentFieldLocation));

	}

	@Test
	public void testTextSearcher2() throws Exception {

		// create data and add a comment for it
		StructureDataType s = new StructureDataType("some-PUSHStruct", 0);
		s.add(new ByteDataType());
		s.add(new WordDataType());

		int txId = program.startTransaction("Search Test");
		try {
			// add data 
			program.getListing().createData(getAddr(0x1001955L), s, s.getLength());
		}
		finally {
			program.endTransaction(txId, true);
		}

		// add a post comment
		addPostComment(0x1001955L, "cause PUSH hit");
		SearchOptions options = new SearchOptions("PUSH", true, true, true, true, true, true, true,
			true, true, true, false, false);
		ProgramLocation startLoc =
			new ProgramLocation(program, program.getMinAddress().getNewAddress(0x1001950L));
		Searcher ts = new ProgramDatabaseSearcher(tool, program, startLoc, null, options, monitor);
		ProgramLocation loc = ts.search();
		assertEquals(getAddr(0x1001955L), loc.getAddress());
		assertTrue("Expected MnemonicFieldLocation, got " + loc.getClass() + " instead!",
			(loc instanceof MnemonicFieldLocation));

		loc = ts.search();
		assertTrue("Expected CommentFieldLocation, got " + loc.getClass() + " instead!",
			(loc instanceof CommentFieldLocation));
		assertEquals(CodeUnit.POST_COMMENT, ((CommentFieldLocation) loc).getCommentType());

	}

	@Test
	public void testTextSearcher3() throws Exception {
		int transactionID = program.startTransaction("test");
		try {
			Function f = program.getFunctionManager().getFunctionAt(getAddr(0));
			f.setRepeatableComment("repeatable comment that has imm to cause a hit");
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		//
		// Test Search All
		SearchOptions options =
			new SearchOptions("imm", true, true, true, true, true, true, true, true, false, // not case sensitive 
				true, false, false);
		ProgramLocation[] locs = searchAll(tool, program, null, null, options, -1, monitor);
		assertNotNull(locs);
//		for (int i = 0; i < locs.length; i++) {
//			System.out.println("" + locs[i]);
//		}
		assertTrue("Expected 9 locations, got " + locs.length, (locs.length == 9));

		options = new SearchOptions("Eax", true, true, true, true, true, true, true, true, true,
			true, false, false);
		locs = searchAll(tool, program, null, null, options, -1, monitor);
		assertNotNull(locs);
		assertEquals(0, locs.length);
	}

	private Address getAddr(long offset) {
		return space.getAddress(offset);
	}

	/**
	 * Find all matches according to search options, starting at the address
	 * in the startLoc.
	 * @param options search options that specify the string to match and where
	 * to look for matches.
	 * @param startLoc location of where to begin search.
	 * @param searchLimit max number of hits to return
	 * @return ProgramLocation[] locations that contain matches.
	 */
	private ProgramLocation[] searchAll(PluginTool pluginTool, Program searchProgram,
			ProgramLocation startLoc, AddressSet set, SearchOptions options, int searchLimit,
			TaskMonitor taskMonitor) {
		int count = 0;
		ArrayList<ProgramLocation> list = new ArrayList<>();
		Searcher ts = new ProgramDatabaseSearcher(pluginTool, searchProgram, startLoc, set, options,
			taskMonitor);
		ProgramLocation loc = null;
		while ((loc = ts.search()) != null) {
			list.add(loc);
			++count;
			if (searchLimit > 0 && count >= searchLimit) {
				break;
			}
		}
		ProgramLocation[] locations = new ProgramLocation[list.size()];
		return list.toArray(locations);
	}
}
