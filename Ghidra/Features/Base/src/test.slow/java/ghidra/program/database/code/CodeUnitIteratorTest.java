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
package ghidra.program.database.code;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.app.plugin.core.bookmark.BookmarkPlugin;
import ghidra.app.plugin.core.clear.ClearPlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.disassembler.DisassemblerPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.plugin.core.script.GhidraScriptMgrPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Test the code manager portion of listing.
 *
 *
 */
public class CodeUnitIteratorTest extends AbstractGhidraHeadedIntegrationTest {

	private Listing listing;
	private AddressSpace space;
	private Program program;
	private Memory mem;
	private int transactionID;
	private TaskMonitor monitor;

	/**
	 * Constructor for CodeManagerTest.
	 * @param arg0
	 */
	public CodeUnitIteratorTest() {
		super();
	}

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {
		monitor = new TaskMonitorAdapter();
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY, this);
		program = builder.getProgram();

		space = program.getAddressFactory().getDefaultAddressSpace();
		listing = program.getListing();
		mem = program.getMemory();
		startTransaction();
		addBlocks("ramblockone", "B1", addr(1000));

		parseStatic(addr(0x3ef), addr(0x3ef));
		parseStatic(addr(0x3f2), addr(0x3f6));
		parseStatic(addr(0x402), addr(0x403));
		parseStatic(addr(0x405), addr(0x406));
		listing.createData(addr(0x3fa), new ByteDataType(), 0);
		listing.createData(addr(0x3fb), new DWordDataType(), 0);
		listing.createData(addr(0x404), new ByteDataType(), 0);
		endTransaction();

	}

	@After
	public void tearDown() throws Exception {
		program.release(this);
	}

	/**
	 * ** Diagnostic Aid ** Open program in tool
	 * @throws Exception
	 */
	private void openProgramInTool() throws Exception {

		TestEnv env = new TestEnv();
		try {
			PluginTool tool = env.getTool();
			tool.addPlugin(CodeBrowserPlugin.class.getName());
			tool.addPlugin(NextPrevAddressPlugin.class.getName());
			tool.addPlugin(DisassemblerPlugin.class.getName());
			tool.addPlugin(ClearPlugin.class.getName());
			tool.addPlugin(GhidraScriptMgrPlugin.class.getName());
			tool.addPlugin(BookmarkPlugin.class.getName());
			tool.addPlugin(GoToAddressLabelPlugin.class.getName());

			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.openProgram(program);

			showTool(tool);

			// Place breakpoint on next line when this method is used for diagnostic
			Msg.info(this, "Opened test program in tool");

			pm.closeAllPrograms(true);
		}
		finally {
			env.dispose();
		}
	}

	@Test
	public void testGetCodeUnits() throws Exception {

		CodeUnitIterator it = listing.getCodeUnits(true);

		for (int i = 0; i < 7; i++) {
			CodeUnit cu = it.next();
			assertEquals(addr(0x3e8 + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}
		CodeUnit cu = it.next();
		assertEquals(addr(0x3ef), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		cu = it.next();
		assertEquals(addr(0x3f1), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3f2 + (2 * i)), cu.getMinAddress());
			assertTrue(cu instanceof Instruction);
		}

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3f8 + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		cu = it.next();
		assertEquals(addr(0x3fb), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3ff + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		cu = it.next();
		assertEquals(addr(0x402), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		cu = it.next();
		assertEquals(addr(0x404), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		cu = it.next();
		assertEquals(addr(0x405), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 617; i++) {
			cu = it.next();
			assertEquals(addr(0x407 + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		// still more in iterator...
		assertTrue(it.hasNext());
		assertNotNull(it.next());

	}

	@Test
	public void testGetCodeUnitsSet() throws Exception {

		AddressSet set = new AddressSet();
		set.addRange(addr(0x3ec), addr(0x3f3));
		set.addRange(addr(0x3fc), addr(0x404));
		set.addRange(addr(0x409), addr(0x40b));

		CodeUnitIterator it = listing.getCodeUnits(set, true);

		for (int i = 0; i < 3; i++) {
			CodeUnit cu = it.next();
			assertEquals(addr(0x3ec + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}
		CodeUnit cu = it.next();
		assertEquals(addr(0x3ef), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		cu = it.next();
		assertEquals(addr(0x3f1), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		cu = it.next();
		assertEquals(addr(0x3f2), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3ff + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		cu = it.next();
		assertEquals(addr(0x402), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		cu = it.next();
		assertEquals(addr(0x404), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x409 + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		assertFalse(it.hasNext());
		assertNull(it.next());
	}

	@Test
	public void testGetCodeUnitsSet2Forward() throws Exception {

		AddressSet set = new AddressSet();
		set.addRange(addr(0x3f2), addr(0x3f2));
		set.addRange(addr(0x3f8), addr(0x3f8));

		CodeUnitIterator it = listing.getCodeUnits(set, true);

		CodeUnit cu = it.next();
		assertEquals(addr(0x3f2), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		cu = it.next();
		assertEquals(addr(0x3f8), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		assertFalse(it.hasNext());
		assertNull(it.next());

	}

	@Test
	public void testGetCodeUnitsSet2Backward() throws Exception {

		AddressSet set = new AddressSet();
		set.addRange(addr(0x3ec), addr(0x3ed));
		set.addRange(addr(0x3f3), addr(0x3f4));

		CodeUnitIterator it = listing.getCodeUnits(set, false);

		CodeUnit cu = it.next();
		assertEquals(addr(0x3f4), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 2; i++) {
			cu = it.next();
			assertEquals(addr(0x3ed - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		assertFalse(it.hasNext());
		assertNull(it.next());
	}

	@Test
	public void testGetCodeUnitsAt() throws Exception {

		CodeUnitIterator it = listing.getCodeUnits(addr(0x3f4), true);
		CodeUnit cu;

		for (int i = 0; i < 2; i++) {
			cu = it.next();
			assertEquals(addr(0x3f4 + (2 * i)), cu.getMinAddress());
			assertTrue(cu instanceof Instruction);
		}

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3f8 + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		cu = it.next();
		assertEquals(addr(0x3fb), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3ff + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		cu = it.next();
		assertEquals(addr(0x402), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		cu = it.next();
		assertEquals(addr(0x404), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		cu = it.next();
		assertEquals(addr(0x405), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 617; i++) {
			cu = it.next();
			assertEquals(addr(0x407 + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		// still more in iterator...
		assertTrue(it.hasNext());
		assertNotNull(it.next());

	}

	@Test
	public void testGetCodeUnitsAt2() throws Exception {

		CodeUnitIterator it = listing.getCodeUnits(addr(0), true);

		for (int i = 0; i < 7; i++) {
			CodeUnit cu = it.next();
			assertEquals(addr(0x3e8 + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}
		CodeUnit cu = it.next();
		assertEquals(addr(0x3ef), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		cu = it.next();
		assertEquals(addr(0x3f1), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3f2 + (2 * i)), cu.getMinAddress());
			assertTrue(cu instanceof Instruction);
		}

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3f8 + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		cu = it.next();
		assertEquals(addr(0x3fb), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3ff + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		cu = it.next();
		assertEquals(addr(0x402), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		cu = it.next();
		assertEquals(addr(0x404), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		cu = it.next();
		assertEquals(addr(0x405), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 617; i++) {
			cu = it.next();
			assertEquals(addr(0x407 + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		// still more in iterator...
		assertTrue(it.hasNext());
		assertNotNull(it.next());

	}

	@Test
	public void testGetCodeUnitsAt3() throws Exception {

		CodeUnitIterator it = listing.getCodeUnits(addr(50000), true);
		assertTrue(!it.hasNext());
		assertNull(it.next());
	}

	@Test
	public void testGetCodeUnitsAt4() throws Exception {

		CodeUnitIterator it = listing.getCodeUnits(addr(0x3fa), true);

		CodeUnit cu = it.next();
		assertEquals(addr(0x3fa), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		cu = it.next();
		assertEquals(addr(0x3fb), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3ff + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		cu = it.next();
		assertEquals(addr(0x402), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		cu = it.next();
		assertEquals(addr(0x404), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		cu = it.next();
		assertEquals(addr(0x405), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 617; i++) {
			cu = it.next();
			assertEquals(addr(0x407 + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		// still more in iterator...
		assertTrue(it.hasNext());
		assertNotNull(it.next());

	}

	@Test
	public void testGetCodeUnitsBackward() throws Exception {

		CodeUnitIterator it = listing.getCodeUnits(false);

		Address addr = addr(0xbe7);
		while (addr.getOffset() >= 0x407) {
			CodeUnit cu = it.next();
			assertEquals(addr, cu.getMinAddress());
			assertTrue(cu instanceof Data);
			addr = addr.previous();
		}

		CodeUnit cu = it.next();
		assertEquals(addr(0x405), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		cu = it.next();
		assertEquals(addr(0x404), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		cu = it.next();
		assertEquals(addr(0x402), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x401 - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		cu = it.next();
		assertEquals(addr(0x3fb), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3fa - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3f6 - (2 * i)), cu.getMinAddress());
			assertTrue(cu instanceof Instruction);
		}

		cu = it.next();
		assertEquals(addr(0x3f1), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		cu = it.next();
		assertEquals(addr(0x3ef), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 7; i++) {
			cu = it.next();
			assertEquals(addr(0x3ee - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		assertTrue(!it.hasNext());
		assertNull(it.next());
	}

	@Test
	public void testGetCodeUnitsBackwardAt() throws Exception {

		CodeUnitIterator it = listing.getCodeUnits(addr(0), false);
		assertTrue(!it.hasNext());
		assertNull(it.next());
	}

	@Test
	public void testGetCodeUnitsBackwardAt2() throws Exception {

		CodeUnitIterator it = listing.getCodeUnits(addr(50000), false);

		Address addr = addr(0xbe7);
		while (addr.getOffset() >= 0x407) {
			CodeUnit cu = it.next();
			assertEquals(addr, cu.getMinAddress());
			assertTrue(cu instanceof Data);
			addr = addr.previous();
		}

		CodeUnit cu = it.next();
		assertEquals(addr(0x405), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		cu = it.next();
		assertEquals(addr(0x404), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		cu = it.next();
		assertEquals(addr(0x402), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x401 - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		cu = it.next();
		assertEquals(addr(0x3fb), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3fa - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3f6 - (2 * i)), cu.getMinAddress());
			assertTrue(cu instanceof Instruction);
		}

		cu = it.next();
		assertEquals(addr(0x3f1), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		cu = it.next();
		assertEquals(addr(0x3ef), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 7; i++) {
			cu = it.next();
			assertEquals(addr(0x3ee - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		assertTrue(!it.hasNext());
		assertNull(it.next());

	}

	@Test
	public void testGetCodeUnitsBackwardAt3() throws Exception {

		CodeUnitIterator it = listing.getCodeUnits(addr(0x3fc), false);

		CodeUnit cu = it.next();
		assertEquals(addr(0x3fb), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3fa - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3f6 - (2 * i)), cu.getMinAddress());
			assertTrue(cu instanceof Instruction);
		}

		cu = it.next();
		assertEquals(addr(0x3f1), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		cu = it.next();
		assertEquals(addr(0x3ef), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 7; i++) {
			cu = it.next();
			assertEquals(addr(0x3ee - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		assertTrue(!it.hasNext());
		assertNull(it.next());

	}

	@Test
	public void testGetCodeUnitsBackwardAt4() throws Exception {

		CodeUnitIterator it = listing.getCodeUnits(addr(0x402), false);

		CodeUnit cu = it.next();
		assertEquals(addr(0x402), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x401 - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		cu = it.next();
		assertEquals(addr(0x3fb), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3fa - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3f6 - (2 * i)), cu.getMinAddress());
			assertTrue(cu instanceof Instruction);
		}

		cu = it.next();
		assertEquals(addr(0x3f1), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		cu = it.next();
		assertEquals(addr(0x3ef), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 7; i++) {
			cu = it.next();
			assertEquals(addr(0x3ee - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		assertTrue(!it.hasNext());
		assertNull(it.next());
	}

	@Test
	public void testGetCodeUnitsBackwardSet() throws Exception {

		AddressSet set = new AddressSet();
		set.addRange(addr(0x3ec), addr(0x3f3));
		set.addRange(addr(0x3fc), addr(0x404));
		set.addRange(addr(0x409), addr(0x40b));

		CodeUnitIterator it = listing.getCodeUnits(set, false);

		for (int i = 0; i < 3; i++) {
			CodeUnit cu = it.next();
			assertEquals(addr(0x40b - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		CodeUnit cu = it.next();
		assertEquals(addr(0x404), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		cu = it.next();
		assertEquals(addr(0x402), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x401 - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		cu = it.next();
		assertEquals(addr(0x3f2), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		cu = it.next();
		assertEquals(addr(0x3f1), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		cu = it.next();
		assertEquals(addr(0x3ef), cu.getMinAddress());
		assertTrue(cu instanceof Instruction);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3ee - i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		assertTrue(!it.hasNext());
		assertNull(it.next());

	}

	@Test
	public void testGetData() throws Exception {
		DataIterator it = listing.getData(true);

		for (int i = 0; i < 7; i++) {
			CodeUnit cu = it.next();
			assertEquals(addr(0x3e8 + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		CodeUnit cu = it.next();
		assertEquals(addr(0x3f1), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3f8 + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		cu = it.next();
		assertEquals(addr(0x3fb), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		for (int i = 0; i < 3; i++) {
			cu = it.next();
			assertEquals(addr(0x3ff + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		cu = it.next();
		assertEquals(addr(0x404), cu.getMinAddress());
		assertTrue(cu instanceof Data);

		for (int i = 0; i < 617; i++) {
			cu = it.next();
			assertEquals(addr(0x407 + i), cu.getMinAddress());
			assertTrue(cu instanceof Data);
		}

		// still more in iterator...
		assertTrue(it.hasNext());
		assertNotNull(it.next());
	}

	@Test
	public void testIteratorForComments() throws Exception {
		startTransaction();
		mem.createInitializedBlock("test", addr(0), 100, (byte) 0, TaskMonitorAdapter.DUMMY_MONITOR,
			false);

		for (int i = 0; i < 20; i++) {
			CodeUnit cu = listing.getCodeUnitAt(addr(i + 10));
			cu.setComment(CodeUnit.PLATE_COMMENT, "comment for plate " + i);
			assertEquals("comment for plate " + i, cu.getComment(CodeUnit.PLATE_COMMENT));
		}
		endTransaction();

		CodeUnitIterator iter =
			listing.getCodeUnitIterator(CodeUnit.COMMENT_PROPERTY, addr(0), true);

		int n = 0;
		Address expectedAddr = null;
		while (iter.hasNext()) {
			CodeUnit cu = iter.next();
			expectedAddr = addr(n + 10);
			assertEquals(expectedAddr, cu.getMinAddress());
			assertNotNull(cu.getComment(CodeUnit.PLATE_COMMENT));
			assertNull(cu.getComment(CodeUnit.EOL_COMMENT));
			++n;
		}
	}

	@Test
	public void testIteratorForCommentType() throws Exception {
		startTransaction();
		mem.createInitializedBlock("test", addr(0), 100, (byte) 0, TaskMonitorAdapter.DUMMY_MONITOR,
			false);
		mem.createInitializedBlock("test2", addr(5000), 100, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		for (int i = 0; i < 20; i++) {
			CodeUnit cu = listing.getCodeUnitAt(addr(i + 10));
			cu.setComment(CodeUnit.PLATE_COMMENT, "comment for plate " + i);
			cu.setComment(CodeUnit.EOL_COMMENT, "comment for eol " + i);
		}

		for (int i = 20; i < 30; i++) {
			CodeUnit cu = listing.getCodeUnitAt(addr(i + 5000));
			cu.setComment(CodeUnit.PLATE_COMMENT, "comment for plate " + i);
			cu.setComment(CodeUnit.EOL_COMMENT, "comment for eol " + i);
		}
		endTransaction();

		CodeUnitIterator iter = ((ProgramDB) program).getCodeManager().getCommentCodeUnitIterator(
			CodeUnit.PLATE_COMMENT, mem);
		int n = 0;
		Address expectedAddr = null;
		while (iter.hasNext()) {
			CodeUnit cu = iter.next();
			if (n < 20) {
				expectedAddr = addr(n + 10);
			}
			else {
				expectedAddr = addr(n + 5000);
			}
			assertEquals(expectedAddr, cu.getMinAddress());
			++n;
		}

		assertEquals(30, n);
	}

	@Test
	public void testIteratorForCommentsBackwards() throws Exception {
		startTransaction();
		mem.createInitializedBlock("test", addr(0), 100, (byte) 0, TaskMonitorAdapter.DUMMY_MONITOR,
			false);

		CodeUnit cu = listing.getCodeUnitAt(addr(90));
		cu.setComment(CodeUnit.PLATE_COMMENT, "comment for plate " + addr(90));

		cu = listing.getCodeUnitAt(addr(80));
		cu.setComment(CodeUnit.PLATE_COMMENT, "comment for plate " + addr(80));

		cu = listing.getCodeUnitAt(addr(70));
		cu.setComment(CodeUnit.PLATE_COMMENT, "comment for plate " + addr(70));

		cu = listing.getCodeUnitAt(addr(10));
		cu.setComment(CodeUnit.PLATE_COMMENT, "comment for plate " + addr(10));

		endTransaction();
		CodeUnitIterator iter =
			listing.getCodeUnitIterator(CodeUnit.COMMENT_PROPERTY, addr(81), false);

		assertTrue(iter.hasNext());

		cu = iter.next();
		assertNotNull(cu);
		assertEquals(addr(80), cu.getMinAddress());

		cu = iter.next();
		assertNotNull(cu);
		assertEquals(addr(70), cu.getMinAddress());

		cu = iter.next();
		assertNotNull(cu);
		assertEquals(addr(10), cu.getMinAddress());

		assertTrue(!iter.hasNext());
		assertNull(iter.next());

	}

	@Test
	public void testGetPropertyCodeUnitIterator() throws Exception {
		startTransaction();
		mem.createInitializedBlock("test", addr(0), 100, (byte) 0, TaskMonitorAdapter.DUMMY_MONITOR,
			false);
		for (int i = 0; i < 20; i++) {
			CodeUnit cu = listing.getCodeUnitAt(addr(i + 10));
			cu.setProperty("Numbers", i);
			assertEquals(i, cu.getIntProperty("Numbers"));
		}
		endTransaction();
		CodeUnitIterator iter = listing.getCodeUnitIterator("Numbers", addr(0), true);
		int n = 0;
		Address expectedAddr = null;
		while (iter.hasNext()) {
			CodeUnit cu = iter.next();
			assertEquals(n, cu.getIntProperty("Numbers"));
			expectedAddr = addr(n + 10);
			assertEquals(expectedAddr, cu.getMinAddress());
			++n;
		}
	}

	@Test
	public void testGetPropertyCuIteratorBackwards() throws Exception {
		startTransaction();
		mem.createInitializedBlock("test", addr(0), 100, (byte) 0, TaskMonitorAdapter.DUMMY_MONITOR,
			false);
		for (int i = 0; i < 20; i++) {
			CodeUnit cu = listing.getCodeUnitAt(addr(i));
			cu.setProperty("Numbers", i);
			assertEquals(i, cu.getIntProperty("Numbers"));
		}
		endTransaction();

		CodeUnitIterator iter = listing.getCodeUnitIterator("Numbers", addr(50), false);
		for (int i = 19; i >= 0; i--) {
			CodeUnit cu = iter.next();
			assertNotNull(cu);
			assertEquals(addr(i), cu.getMinAddress());
		}
		assertTrue(!iter.hasNext());
		assertNull(iter.next());
	}

	@Test
	public void testGetPropertCUIteratorSet() throws Exception {
		startTransaction();
		mem.createInitializedBlock("bk1", addr(0), 200, (byte) 0, TaskMonitorAdapter.DUMMY_MONITOR,
			false);
		// addresses 10-19
		for (int i = 0; i < 20; i++) {
			CodeUnit cu = listing.getCodeUnitAt(addr(i + 10));
			cu.setProperty("Numbers", i);
			assertEquals(i, cu.getIntProperty("Numbers"));
		}
		// addresses 100-119
		for (int i = 100; i < 120; i++) {
			CodeUnit cu = listing.getCodeUnitAt(addr(i));
			cu.setProperty("Numbers", i);
			assertEquals(i, cu.getIntProperty("Numbers"));
		}
		endTransaction();
		AddressSet set = new AddressSet(addr(0), addr(5));
		set.addRange(addr(18), addr(20));
		set.addRange(addr(50), addr(101));
		CodeUnitIterator iter = listing.getCodeUnitIterator("Numbers", set, true);
		CodeUnit cu = iter.next();
		assertEquals(addr(18), cu.getMinAddress());
		cu = iter.next();
		assertEquals(addr(19), cu.getMinAddress());
		cu = iter.next();
		assertEquals(addr(20), cu.getMinAddress());
		cu = iter.next();
		assertEquals(addr(100), cu.getMinAddress());
		cu = iter.next();
		assertEquals(addr(101), cu.getMinAddress());
		assertTrue(!iter.hasNext());
	}

	@Test
	public void testPropertyCommentIterator() throws Exception {
		startTransaction();
// 		mem.createUninitializedBlock("Test", addr(0), 200);
		mem.createInitializedBlock("bk1", addr(0), 200, (byte) 0, TaskMonitorAdapter.DUMMY_MONITOR,
			false);
		for (int i = 0; i < 20; i++) {
			CodeUnit cu = listing.getCodeUnitAt(addr(i + 10));
			cu.setComment(CodeUnit.EOL_COMMENT, "This is an eol comment " + i);
			assertNotNull(cu.getComment(CodeUnit.EOL_COMMENT));
		}
		for (int i = 100; i < 120; i++) {
			CodeUnit cu = listing.getCodeUnitAt(addr(i));
			cu.setComment(CodeUnit.PRE_COMMENT, "This is pre comment " + i);
		}
		endTransaction();
		AddressSet set = new AddressSet(addr(0), addr(5));
		set.addRange(addr(18), addr(20));
		set.addRange(addr(50), addr(101));
		CodeUnitIterator iter = listing.getCodeUnitIterator(CodeUnit.COMMENT_PROPERTY, set, true);
		assertTrue(iter.hasNext());
		CodeUnit cu = iter.next();
		assertEquals(addr(18), cu.getMinAddress());
		cu = iter.next();
		assertEquals(addr(19), cu.getMinAddress());
		cu = iter.next();
		assertEquals(addr(20), cu.getMinAddress());
		cu = iter.next();
		assertEquals(addr(100), cu.getMinAddress());
		cu = iter.next();
		assertEquals(addr(101), cu.getMinAddress());
		assertTrue(!iter.hasNext());

	}

	@Test
	public void testPropertyInstructionIterator() throws Exception {
		startTransaction();
		addBlocks("ramblocktwo", "B2", addr(10000));
		addBlocks("ramblockthree", "B3", addr(21000));

		listing.clearCodeUnits(addr(0x3ef), addr(0x406), false);

		parseStatic(addr(1100), addr(1500));
		AddressSet set = new AddressSet(addr(0), addr(20));
		set.addRange(addr(1100), addr(1600));
		CodeUnitIterator iter =
			listing.getCodeUnitIterator(CodeUnit.INSTRUCTION_PROPERTY, set, true);
		CodeUnit cu = iter.next();
		assertNotNull(cu);
		assertEquals(addr(1100), cu.getMinAddress());

		cu = iter.next();
		assertNotNull(cu);
		assertEquals(addr(1102), cu.getMinAddress());

		cu = iter.next();
		assertNotNull(cu);
		assertEquals(addr(1104), cu.getMinAddress());

		endTransaction();
	}

	@Test
	public void testInstructionIterator() throws Exception {
		startTransaction();
		addBlocks("ramblocktwo", "B2", addr(10000));

		listing.clearCodeUnits(addr(0x3ef), addr(0x406), false);

		parseStatic(addr(1100), addr(1500));

		InstructionIterator iter = listing.getInstructions(true);
		Instruction inst = iter.next();
		assertNotNull(inst);
		assertEquals(addr(1100), inst.getMinAddress());

		inst = iter.next();
		assertNotNull(inst);
		assertEquals(addr(1102), inst.getMinAddress());

		inst = iter.next();
		assertNotNull(inst);
		assertEquals(addr(1104), inst.getMinAddress());

		while (iter.hasNext()) {
			inst = iter.next();
			assertNotNull(inst);
		}
		assertEquals(addr(1500), inst.getMinAddress());

		parseStatic(addr(1700), addr(1705));
		parseStatic(addr(1801), addr(2453));
		parseStatic(addr(10000), addr(10100));

		endTransaction();

		int instCount = 0;
		int instLen = 0;
		InstructionIterator instIt = listing.getInstructions(true);
		while (instIt.hasNext()) {
			inst = instIt.next();
			instCount++;
			instLen += inst.getLength();
		}

		assertEquals(582, instCount);
		assertEquals(1164, instLen);

		assertEquals(582, listing.getNumInstructions());
	}

	@Test
	public void testGetInstructionsInSet() throws Exception {
		startTransaction();
		addBlocks("ramblocktwo", "B2", addr(10000));

		parseStatic(addr(1100), addr(1500));
		parseStatic(addr(1700), addr(1705));
		parseStatic(addr(1801), addr(2453));
		parseStatic(addr(10000), addr(10100));
		endTransaction();

		AddressSet set = new AddressSet(addr(100), addr(500));
		set.addRange(addr(1800), addr(2000));
		set.addRange(addr(8000), addr(9000));

		InstructionIterator iter = listing.getInstructions(set, true);
		assertTrue(iter.hasNext());
		Instruction inst = iter.next();
		assertEquals(addr(1801), inst.getMinAddress());

		while (iter.hasNext()) {
			inst = iter.next();
			assertNotNull(inst);
		}
		assertTrue(inst.getMinAddress().compareTo(addr(2000)) <= 0);
	}

	@Test
	public void testGetInstructionsInSetBackwards() throws Exception {

		startTransaction();
		mem.removeBlock(mem.getBlock(addr(1000)), monitor);

		addBlocks("ramblockone", "B1", addr(0x44c));

		listing.clearCodeUnits(addr(0x44c), addr(0x476), false);
		parseStatic(addr(0x44c), addr(0x462));
		parseStatic(addr(0x466), addr(0x46f));
		parseStatic(addr(0x475), addr(0x476));
		endTransaction();

		assertNotNull(listing.getInstructionAt(addr(0x462)));
		AddressSet set = new AddressSet(addr(0x44f), addr(0x454));
		set.addRange(addr(0x45e), addr(0x45f));
		set.addRange(addr(0x462), addr(0x465));

		InstructionIterator iter = listing.getInstructions(set, false);
		assertTrue(iter.hasNext());
		Instruction inst = iter.next();
		assertEquals(addr(0x462), inst.getMinAddress());

		inst = iter.next();
		assertNotNull(inst);
		assertEquals(addr(0x45e), inst.getMinAddress());

		inst = iter.next();
		assertNotNull(inst);
		assertEquals(addr(0x454), inst.getMinAddress());

		inst = iter.next();
		assertNotNull(inst);
		assertEquals(addr(0x452), inst.getMinAddress());

		inst = iter.next();
		assertNotNull(inst);
		assertEquals(addr(0x450), inst.getMinAddress());

		assertTrue(!iter.hasNext());
		assertNull(iter.next());
	}

	@Test
	public void testGetInstructionsBackwardsAt() throws Exception {

		startTransaction();
		mem.removeBlock(mem.getBlock(addr(1000)), monitor);

		addBlocks("ramblockone", "B1", addr(0x44c));

		listing.clearCodeUnits(addr(0x44c), addr(0x476), false);
		parseStatic(addr(0x44c), addr(0x462));
		parseStatic(addr(0x466), addr(0x46f));
		parseStatic(addr(0x475), addr(0x476));
		listing.clearCodeUnits(addr(0x457), addr(0x46d), false);
		endTransaction();

		InstructionIterator iter = listing.getInstructions(addr(0x462), false);
		assertTrue(iter.hasNext());
		Instruction inst = iter.next();
		assertNotNull(inst);
		assertEquals(addr(0x454), inst.getMinAddress());

		inst = iter.next();
		assertNotNull(inst);
		assertEquals(addr(0x452), inst.getMinAddress());

		inst = iter.next();
		assertNotNull(inst);
		assertEquals(addr(0x450), inst.getMinAddress());

		inst = iter.next();
		assertNotNull(inst);
		assertEquals(addr(0x44e), inst.getMinAddress());

		inst = iter.next();
		assertNotNull(inst);
		assertEquals(addr(0x44c), inst.getMinAddress());

		assertTrue(!iter.hasNext());
		assertNull(iter.next());
	}

	@Test
	public void testGetDataBackwards() throws Exception {
		startTransaction();
		mem.createInitializedBlock("test", addr(0), 1000, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		for (int i = 0; i < 10; i++) {
			listing.createData(addr(i), DataType.DEFAULT, 1);
		}

		Structure struct = new StructureDataType("struct_1", 100);
		Structure struct2 = new StructureDataType("struct_2", 0);
		Structure struct3 = new StructureDataType("struct_3", 0);
		DataTypeManager dtm = new StandAloneDataTypeManager("dummyDTM");
		int id = dtm.startTransaction("");
		struct = (Structure) dtm.resolve(struct, null);
		struct2 = (Structure) dtm.resolve(struct2, null);
		struct3 = (Structure) dtm.resolve(struct3, null);

		struct2.add(new ByteDataType());
		struct2.add(new StringDataType(), 20);
		struct2.add(new QWordDataType());
		struct3.add(struct2);

		struct.replace(0, struct2, struct2.getLength());
		struct.replace(1, new StringDataType(), 10);

		listing.createData(addr(12), struct, 0);
		listing.createData(addr(300), struct2, 0);
		listing.createData(addr(250), struct3, 0);

		listing.createData(addr(500), new QWordDataType(), 0);
		listing.createData(addr(550), new FloatDataType(), 0);

		for (int i = 0; i < 10; i++) {
			listing.createData(addr(i + 600), new ByteDataType(), 1);
		}

		endTransaction();

		AddressSet set = new AddressSet();
		set.addRange(addr(5), addr(8));
		set.addRange(addr(200), addr(300));
		set.addRange(addr(600), addr(605));

		DataIterator iter = listing.getDefinedData(set, false);
		for (int i = 5; i >= 0; i--) {
			Data d = iter.next();
			assertNotNull(d);
			assertEquals(addr(600 + i), d.getMinAddress());
		}
		dtm.endTransaction(id, true);
		dtm.close();
	}

	@Test
	public void testGetCompositeData() throws Exception {
		startTransaction();
		mem.createInitializedBlock("test", addr(0), 1000, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		Structure struct = new StructureDataType("struct_1", 100);
		Structure struct2 = new StructureDataType("struct_2", 0);
		Structure struct3 = new StructureDataType("struct_3", 0);
		DataTypeManager dtm = new StandAloneDataTypeManager("dummyDTM");
		int id = dtm.startTransaction("");

		struct = (Structure) dtm.resolve(struct, null);
		struct2 = (Structure) dtm.resolve(struct2, null);
		struct3 = (Structure) dtm.resolve(struct3, null);

		struct2.add(new ByteDataType());
		struct2.add(new StringDataType(), 20);
		struct2.add(new QWordDataType());
		struct3.add(struct2);

		struct.replace(0, struct2, struct2.getLength());
		struct.replace(1, new StringDataType(), 10);

		listing.createData(addr(0), struct, 0);

		listing.createData(addr(300), struct2, 0);

		listing.createData(addr(250), struct3, 0);
		endTransaction();

		DataIterator iter = listing.getCompositeData(true);
		assertTrue(iter.hasNext());
		Data d = iter.next();
		assertNotNull(d);
		assertEquals(addr(0), d.getMinAddress());
		assertEquals(addr(99), d.getMaxAddress());

		d = iter.next();
		assertNotNull(d);
		assertEquals(addr(250), d.getMinAddress());
		assertEquals("struct_3", d.getDataType().getName());

		d = iter.next();
		assertNotNull(d);
		assertEquals(addr(300), d.getMinAddress());
		assertEquals(3, d.getNumComponents());

		assertTrue(!iter.hasNext());
		d = iter.next();
		assertNull(d);
		dtm.endTransaction(id, true);
		dtm.close();
	}

	@Test
	public void testGetCompositeDataStartingAt() throws Exception {
		startTransaction();
		mem.createInitializedBlock("test", addr(0), 1000, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		Structure struct = new StructureDataType("struct_1", 100);
		Structure struct2 = new StructureDataType("struct_2", 0);
		Structure struct3 = new StructureDataType("struct_3", 0);
		DataTypeManager dtm = new StandAloneDataTypeManager("dummyDTM");
		int id = dtm.startTransaction("");
		struct = (Structure) dtm.resolve(struct, null);
		struct2 = (Structure) dtm.resolve(struct2, null);
		struct3 = (Structure) dtm.resolve(struct3, null);

		struct2.add(new ByteDataType());
		struct2.add(new StringDataType(), 20);
		struct2.add(new QWordDataType());
		struct3.add(struct2);

		struct.replace(0, struct2, struct2.getLength());
		struct.replace(1, new StringDataType(), 10);

		listing.createData(addr(0), struct, 0);

		listing.createData(addr(300), struct2, 0);

		listing.createData(addr(250), struct3, 0);

		Union union = new UnionDataType("union_1");
		union.add(struct3);
		union.add(struct2);

		listing.createData(addr(600), union, 0);
		endTransaction();

		DataIterator iter = listing.getCompositeData(addr(275), true);
		assertTrue(iter.hasNext());

		Data d = iter.next();
		assertNotNull(d);
		assertEquals(addr(300), d.getMinAddress());

		d = iter.next();
		assertNotNull(d);
		assertEquals(addr(600), d.getMinAddress());

		assertTrue(!iter.hasNext());
		assertNull(iter.next());
		dtm.endTransaction(id, true);
		dtm.close();

	}

	@Test
	public void testGetCompositeDataInSet() throws Exception {
		startTransaction();
		mem.createInitializedBlock("test", addr(0), 1000, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		Structure struct = new StructureDataType("struct_1", 100);
		Structure struct2 = new StructureDataType("struct_2", 0);
		Structure struct3 = new StructureDataType("struct_3", 0);
		DataTypeManager dtm = new StandAloneDataTypeManager("dummyDTM");
		int id = dtm.startTransaction("");
		struct = (Structure) dtm.resolve(struct, null);
		struct2 = (Structure) dtm.resolve(struct2, null);
		struct3 = (Structure) dtm.resolve(struct3, null);

		struct2.add(new ByteDataType());
		struct2.add(new StringDataType(), 20);
		struct2.add(new QWordDataType());
		struct3.add(struct2);

		struct.replace(0, struct2, struct2.getLength());
		struct.replace(1, new StringDataType(), 10);

		listing.createData(addr(0), struct, 0);

		listing.createData(addr(300), struct2, 0);

		listing.createData(addr(450), struct3, 0);

		Union union = new UnionDataType("union_1");
		union.add(struct3);
		union.add(struct2);

		listing.createData(addr(800), union, 0);
		endTransaction();

		AddressSet set = new AddressSet();
		set.addRange(addr(5), addr(10));
		set.addRange(addr(100), addr(200));
		set.addRange(addr(300), addr(320));
		set.addRange(addr(400), addr(500));

		DataIterator iter = listing.getCompositeData(set, true);
		Data d = iter.next();
		assertNotNull(d);
		assertEquals(addr(300), d.getMinAddress());
		d = iter.next();
		assertNotNull(d);
		assertEquals(addr(450), d.getMinAddress());

		d = iter.next();
		assertNull(d);
		dtm.endTransaction(id, true);
		dtm.close();

	}

	@Test
	public void testGetDefinedDataIterator() throws Exception {
		startTransaction();
		mem.removeBlock(mem.getBlock(addr(1000)), monitor);
		mem.createInitializedBlock("test", addr(0), 1000, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		for (int i = 0; i < 10; i++) {
			listing.createData(addr(i), new ByteDataType(), 1);
		}

		Structure struct = new StructureDataType("struct_1", 100);
		Structure struct2 = new StructureDataType("struct_2", 0);
		Structure struct3 = new StructureDataType("struct_3", 0);
		DataTypeManager dtm = new StandAloneDataTypeManager("dummyDTM");
		int id = dtm.startTransaction("");
		struct = (Structure) dtm.resolve(struct, null);
		struct2 = (Structure) dtm.resolve(struct2, null);
		struct3 = (Structure) dtm.resolve(struct3, null);

		struct2.add(new ByteDataType());
		struct2.add(new StringDataType(), 20);
		struct2.add(new QWordDataType());
		struct3.add(struct2);

		struct.replace(0, struct2, struct2.getLength());
		struct.replace(1, new StringDataType(), 10);

		listing.createData(addr(12), struct, 0);
		listing.createData(addr(300), struct2, 0);
		listing.createData(addr(250), struct3, 0);

		listing.createData(addr(500), new QWordDataType(), 0);
		listing.createData(addr(550), new FloatDataType(), 0);
		endTransaction();

		DataIterator iter = listing.getDefinedData(true);
		for (int i = 0; i < 10; i++) {
			Data d = iter.next();
			assertNotNull(d);
			assertEquals(addr(i), d.getMinAddress());
		}

		Data d = iter.next();
		assertNotNull(d);
		assertEquals(addr(12), d.getMinAddress());
		assertEquals("struct_1", d.getDataType().getName());

		d = iter.next();
		assertNotNull(d);
		assertEquals(addr(250), d.getMinAddress());
		assertEquals("struct_3", d.getDataType().getName());

		d = iter.next();
		assertNotNull(d);
		assertEquals(addr(300), d.getMinAddress());
		assertEquals("struct_2", d.getDataType().getName());

		d = iter.next();
		assertNotNull(d);
		assertEquals(addr(500), d.getMinAddress());
		assertTrue(d.getDataType() instanceof QWordDataType);

		d = iter.next();
		assertNotNull(d);
		assertEquals(addr(550), d.getMinAddress());
		assertTrue(d.getDataType() instanceof FloatDataType);

		assertTrue(!iter.hasNext());
		dtm.endTransaction(id, true);
		dtm.close();
	}

	@Test
	public void testGetDefinedDataAtIterator() throws Exception {
		startTransaction();
		mem.removeBlock(mem.getBlock(addr(1000)), monitor);
		mem.createInitializedBlock("test", addr(0), 1000, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		for (int i = 0; i < 10; i++) {
			listing.createData(addr(i), DataType.DEFAULT, 1);
		}

		Structure struct = new StructureDataType("struct_1", 100);
		Structure struct2 = new StructureDataType("struct_2", 0);
		Structure struct3 = new StructureDataType("struct_3", 0);
		DataTypeManager dtm = new StandAloneDataTypeManager("dummyDTM");
		int id = dtm.startTransaction("");
		struct = (Structure) dtm.resolve(struct, null);
		struct2 = (Structure) dtm.resolve(struct2, null);
		struct3 = (Structure) dtm.resolve(struct3, null);

		struct2.add(new ByteDataType());
		struct2.add(new StringDataType(), 20);
		struct2.add(new QWordDataType());
		struct3.add(struct2);

		struct.replace(0, struct2, struct2.getLength());
		struct.replace(1, new StringDataType(), 10);

		listing.createData(addr(12), struct, 0);
		listing.createData(addr(300), struct2, 0);
		listing.createData(addr(250), struct3, 0);

		listing.createData(addr(500), new QWordDataType(), 0);
		listing.createData(addr(550), new FloatDataType(), 0);
		endTransaction();

		DataIterator iter = listing.getDefinedData(addr(250), true);

		Data d = iter.next();
		assertNotNull(d);
		assertEquals(addr(250), d.getMinAddress());
		assertEquals("struct_3", d.getDataType().getName());

		d = iter.next();
		assertNotNull(d);
		assertEquals(addr(300), d.getMinAddress());
		assertEquals("struct_2", d.getDataType().getName());

		d = iter.next();
		assertNotNull(d);
		assertEquals(addr(500), d.getMinAddress());
		assertTrue(d.getDataType() instanceof QWordDataType);

		d = iter.next();
		assertNotNull(d);
		assertEquals(addr(550), d.getMinAddress());
		assertTrue(d.getDataType() instanceof FloatDataType);

		assertTrue(!iter.hasNext());
		dtm.endTransaction(id, true);
		dtm.close();
	}

	@Test
	public void testGetDefinedDataSetIterator() throws Exception {
		startTransaction();
		mem.createInitializedBlock("test", addr(0), 1000, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		for (int i = 0; i < 10; i++) {
			listing.createData(addr(i), new ByteDataType(), 0);
		}

		Structure struct = new StructureDataType("struct_1", 100);
		Structure struct2 = new StructureDataType("struct_2", 0);
		Structure struct3 = new StructureDataType("struct_3", 0);
		DataTypeManager dtm = new StandAloneDataTypeManager("dummyDTM");
		int id = dtm.startTransaction("");
		struct = (Structure) dtm.resolve(struct, null);
		struct2 = (Structure) dtm.resolve(struct2, null);
		struct3 = (Structure) dtm.resolve(struct3, null);

		struct2.add(new ByteDataType());
		struct2.add(new StringDataType(), 20);
		struct2.add(new QWordDataType());
		struct3.add(struct2);

		struct.replace(0, struct2, struct2.getLength());
		struct.replace(1, new StringDataType(), 10);

		listing.createData(addr(12), struct, 0);
		listing.createData(addr(300), struct2, 0);
		listing.createData(addr(250), struct3, 0);

		listing.createData(addr(500), new QWordDataType(), 0);
		listing.createData(addr(550), new FloatDataType(), 0);

		for (int i = 0; i < 10; i++) {
			listing.createData(addr(i + 600), new ByteDataType(), 0);
		}
		endTransaction();

		AddressSet set = new AddressSet();
		set.addRange(addr(5), addr(8));
		set.addRange(addr(200), addr(300));
		set.addRange(addr(600), addr(605));

		DataIterator iter = listing.getDefinedData(set, true);
		for (int i = 5; i < 9; i++) {
			Data d = iter.next();
			assertNotNull(d);
			assertEquals(addr(i), d.getMinAddress());
		}

		Data d = iter.next();
		assertNotNull(d);
		assertEquals(addr(250), d.getMinAddress());
		assertEquals("struct_3", d.getDataType().getName());

		d = iter.next();
		assertNotNull(d);
		assertEquals(addr(300), d.getMinAddress());
		assertEquals("struct_2", d.getDataType().getName());

		for (int i = 600; i < 606; i++) {
			d = iter.next();
			assertNotNull(d);
			assertEquals(addr(i), d.getMinAddress());
		}
		assertTrue(!iter.hasNext());
		dtm.endTransaction(id, true);
		dtm.close();
	}

	@Test
	public void test8051CodeUnitIterator() throws Exception {

		program.release(this);
		ProgramBuilder builder = new ProgramBuilder("8051", ProgramBuilder._8051, this);

		builder.createMemory("CODE", "CODE:0100", 0x100);
		builder.createMemory("EXTMEM", "EXTMEM:0000", 0x100);
		builder.createMemory("SFR", "SFR:0000", 0x100);

		for (int i = 0; i < 10; i++) {
			builder.applyDataType("CODE:010" + i, ByteDataType.dataType, 1);
		}

		for (int i = 0; i < 10; i++) {
			builder.applyDataType("EXTMEM:000" + i, ByteDataType.dataType, 1);
		}

		for (int i = 0; i < 10; i++) {
			builder.applyDataType("SFR:000" + i, ByteDataType.dataType, 1);
		}

		program = builder.getProgram();

		// make sure we can get an interator over multiple address spaces
		CodeUnitIterator iter = program.getListing().getCodeUnits(true);
		int cnt = 0;
		while (iter.hasNext()) {
			iter.next();
			++cnt;
		}
		assertEquals(0x300, cnt);
	}

	@Test
	public void test8051CodeUnitIteratorUsingPropertyMethod() throws Exception {
		program.release(this);
		ProgramBuilder builder = new ProgramBuilder("8051", ProgramBuilder._8051, this);

		builder.createMemory("CODE", "CODE:0100", 0x100);
		builder.createMemory("EXTMEM", "EXTMEM:0000", 0x100);
		builder.createMemory("SFR", "SFR:0000", 0x100);

		builder.disassemble("CODE:0100", 10);

		program = builder.getProgram();

		// make sure we can get an interator over multiple address spaces
		CodeUnitIterator iter =
			program.getListing().getCodeUnitIterator(CodeUnit.INSTRUCTION_PROPERTY, true);
		int cnt = 0;
		while (iter.hasNext()) {
			iter.next();
			++cnt;
		}
		assertEquals(10, cnt);
	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

	private void addBlocks(String resourceName, String blockName, Address blockStart)
			throws Exception {
		mem.createInitializedBlock(blockName, blockStart, 0x800, (byte) 0, monitor, false);
	}

	private void parseStatic(Address startAddr, Address endAddr) throws Exception {

		Address addr;

		for (addr = startAddr; addr.compareTo(endAddr) <= 0;) {
			parseOne(addr);
			CodeUnit unit = listing.getCodeUnitAt(addr);
			addr = addr.add(unit.getLength());
		}
	}

	private void parseOne(Address atAddr) throws Exception {

		MemBuffer buf = new DumbMemBufferImpl(mem, atAddr);
		ProcessorContext context = new ProgramProcessorContext(program.getProgramContext(), atAddr);
		InstructionPrototype proto = program.getLanguage().parse(buf, context, false);

		listing.createInstruction(atAddr, proto, buf, context);
	}

	private void startTransaction() {
		transactionID = program.startTransaction("Test");
	}

	private void endTransaction() {
		program.endTransaction(transactionID, true);
	}
}
