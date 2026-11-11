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
package ghidra.app.plugin.core.analysis;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Tests {@link NDS32ITBAnalyzer}'s validation of IT-table entries
 * referenced by {@code ex9.it} sites.  Specifically, entries whose
 * 4 bytes themselves decode to another {@code ex9.it} (a recursive
 * dispatch) are flagged with a {@code WARNING} bookmark under the
 * "NDS32 ITB" category -- on hardware such an entry would raise a
 * Reserved Instruction Exception.  Valid entries are annotated with
 * an EOL comment showing the effective instruction.
 *
 * <p>Source listing the byte map was assembled from:
 * <pre>
 *     .text
 *     .org 0x0000
 *     sethi $r0, hi20(0x1000)
 *     ori   $r0, $r0, lo12(0x1000)
 *     mtusr $r0, $itb
 *     ex9.it 0          ! IT[0]: recursive (invalid)
 *     ex9.it 2          ! IT[2]: valid (add r0,r1,r2)
 *     j .
 *
 *     .org 0x1000, 0xff
 *     ex9.it 0x20       ! IT[0]: nested ex9.it -> recursive
 *     nop16             !        + 2 bytes filler
 *     ! IT[1] is unused in this test.
 *     add $r0, $r1, $r2 ! IT[2]: valid instruction
 * </pre>
 */
public class NDS32ITBValidationTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String LANGUAGE = "NDS32:LE:32:default";
	private static final String ITB_BOOKMARK_CATEGORY = "NDS32 ITB";

	private TestEnv env;
	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		builder = new ProgramBuilder("itb-validation", LANGUAGE);
		builder.createMemory("ram", "0x0", 0x2000);

		byte[] fill = new byte[0x2000];
		java.util.Arrays.fill(fill, (byte) 0xff);
		builder.setBytes("0x0000", fill);

		// Initialization: r0 = 0x1000, mtusr r0,itb.
		builder.setBytes("0x0000",
			"46 00 00 01 58 00 00 00 42 0e 00 21");
		// ex9.it sites: imm=0 (recursive entry) and imm=2 (valid).
		builder.setBytes("0x000c", "dd 40 dd 42 48 00 00 00");

		// IT table at 0x1000.  IT[0] is a nested ex9.it (recursive),
		// IT[1] is data padding (the surrounding 0xff fill provides it),
		// IT[2] is a valid 32-bit `add` instruction.
		builder.setBytes("0x1000", "ea 20 92 00");
		// IT[1] @ 0x1004 stays 0xffffffff from the fill.
		builder.setBytes("0x1008", "40 00 88 00");

		program = builder.getProgram();

		int txId = program.startTransaction("disassemble");
		try {
			new DisassembleCommand(addr(0x0000), null, true).applyTo(program,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		// Run the ITB analyzer directly so the test does not depend on
		// auto-analysis scheduling.
		int analysisTx = program.startTransaction("itb-analysis");
		try {
			NDS32ITBAnalyzer itb = new NDS32ITBAnalyzer();
			itb.added(program, program.getMemory(), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(analysisTx, true);
		}
	}

	@After
	public void tearDown() throws Exception {
		if (env != null) {
			env.dispose();
		}
	}

	@Test
	public void recursiveEntryIsFlagged() {
		// IT[0] = nested ex9.it.  Expect a WARNING bookmark whose
		// message mentions either "nested ex9.it" or "Reserved
		// Instruction Exception".
		Bookmark bm = findItbWarning(0x000c);
		assertNotNull(
			"ex9.it 0 (recursive IT[0]) should have a WARNING bookmark",
			bm);
		String comment = bm.getComment();
		assertTrue(
			"recursive-entry message should mention nesting or reserved insn: "
				+ comment,
			comment.contains("nested ex9.it") ||
				comment.contains("Reserved Instruction"));
	}

	@Test
	public void validEntryHasNoWarning() {
		// IT[2] = add r0,r1,r2.  No WARNING bookmark expected.
		assertNull(
			"ex9.it 2 (valid IT[2]) should NOT have a WARNING bookmark",
			findItbWarning(0x000e));
	}

	@Test
	public void validEntryReceivesEolComment() {
		// The analyzer annotates valid sites with an EOL comment
		// containing the effective instruction.
		String eol = program.getListing()
				.getComment(CodeUnit.EOL_COMMENT, addr(0x000e));
		assertNotNull("ex9.it 2 should receive an EOL comment", eol);
		assertTrue(
			"EOL comment should describe the effective `add` instruction: "
				+ eol,
			eol.toLowerCase().contains("add"));
	}

	@Test
	public void writerIsDiscovered() {
		// The mtusr,itb writer at 0x0008 should be discovered and
		// bookmarked under the "NDS32 ITB" category as INFO.
		Bookmark[] bms = program.getBookmarkManager()
				.getBookmarks(addr(0x0008), BookmarkType.INFO);
		boolean found = false;
		for (Bookmark b : bms) {
			if (ITB_BOOKMARK_CATEGORY.equals(b.getCategory())) {
				found = true;
				break;
			}
		}
		assertTrue("ITB writer at 0x0008 should be bookmarked as INFO",
			found);
	}

	private Bookmark findItbWarning(long off) {
		for (Bookmark b : program.getBookmarkManager()
				.getBookmarks(addr(off), BookmarkType.WARNING)) {
			if (ITB_BOOKMARK_CATEGORY.equals(b.getCategory())) {
				return b;
			}
		}
		return null;
	}

	private Address addr(long off) {
		return program.getAddressFactory().getDefaultAddressSpace()
				.getAddress(off);
	}
}
