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

import java.math.BigInteger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Tests {@link NDS32ITBAnalyzer}'s handling of programs that contain
 * multiple {@code mtusr,itb} writers -- the typical firmware-overlay
 * shape where a ROM and a later-loaded firmware each install their
 * own IT table.
 *
 * <p>The analyzer is expected to:
 * <ul>
 * <li>discover both writers and emit an INFO bookmark for each,</li>
 * <li>elect the higher-address writer's value as the active ITB
 *     (firmware wins over ROM),</li>
 * <li>annotate every {@code ex9.it} site -- in either region -- with
 *     the effective instruction it dispatches under the active
 *     table.</li>
 * </ul>
 *
 * <p>Source listing the byte map was assembled from:
 * <pre>
 *     ! 0x0000  ROM init + 4 ex9.it sites; ITB = 0x1000.
 *     ! 0x0100  L_target1 (movi r5,0x11)
 *     ! 0x0180  L_target2 (movi r5,0x22)
 *     ! 0x01c0  L_done    (j .)
 *     ! 0x1000  ROM IT table: add / add333+nop / j L_target1 / lwi a0,[a1+4]
 *     ! 0x2000  FW  init + 4 ex9.it sites; ITB = 0x3000.
 *     ! 0x3000  FW  IT table: sub / ori a0,a0,0xaa / j L_target2 / lwi a3,[a1+8]
 * </pre>
 */
public class NDS32ITBMultipleWritersTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final String LANGUAGE = "NDS32:LE:32:default";
	private static final String ITB_BOOKMARK_CATEGORY = "NDS32 ITB";

	/** ROM mtusr,itb writer address. */
	private static final long ROM_WRITER = 0x0008L;
	/** Firmware mtusr,itb writer address. */
	private static final long FW_WRITER = 0x2008L;
	/** ITB value installed by the ROM writer. */
	private static final long ROM_ITB = 0x1000L;
	/** ITB value installed by the FW writer (the expected "active" value). */
	private static final long FW_ITB = 0x3000L;

	private TestEnv env;
	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		builder = new ProgramBuilder("itb-multi", LANGUAGE);
		builder.createMemory("ram", "0x0", 0x4000);

		byte[] fill = new byte[0x4000];
		java.util.Arrays.fill(fill, (byte) 0xff);
		builder.setBytes("0x0000", fill);

		// ROM init: r0 = 0x1000, mtusr r0,itb.
		builder.setBytes("0x0000",
			"46 00 00 01 58 00 00 00 42 0e 00 21");
		// ROM ex9.it sites (imm = 0..3) and terminator j L_done.
		builder.setBytes("0x000c", "dd 40 dd 41 dd 42 dd 43 48 00 00 d6");

		// L_target1 / L_target2 / L_done.
		builder.setBytes("0x0100", "44 50 00 11 48 00 00 5e");
		builder.setBytes("0x0180", "44 50 00 22 48 00 00 1e");
		builder.setBytes("0x01c0", "48 00 00 00");

		// ROM IT table.
		builder.setBytes("0x1000",
			"40 00 88 00 98 0a 92 00 48 ff f8 7c 04 00 80 01");

		// FW init: r0 = 0x3000, mtusr r0,itb.
		builder.setBytes("0x2000",
			"46 00 00 03 58 00 00 00 42 0e 00 21");
		// FW ex9.it sites (imm = 0..3) and terminator j L_done.
		builder.setBytes("0x200c", "dd 40 dd 41 dd 42 dd 43 48 ff f0 d6");

		// FW IT table.
		builder.setBytes("0x3000",
			"40 00 88 01 58 00 00 aa 48 ff e8 bc 04 30 80 02");

		program = builder.getProgram();

		int txId = program.startTransaction("disassemble");
		try {
			new DisassembleCommand(addr(0x0000), null, true).applyTo(program,
				TaskMonitor.DUMMY);
			new DisassembleCommand(addr(0x2000), null, true).applyTo(program,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

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
	public void bothWritersAreBookmarked() {
		// Each writer should receive an INFO bookmark from the
		// discoverAllItbCandidates pass.
		assertNotNull("ROM writer at 0x" + Long.toHexString(ROM_WRITER) +
			" should have an INFO bookmark",
			findItbBookmark(ROM_WRITER, BookmarkType.INFO));
		assertNotNull("FW writer at 0x" + Long.toHexString(FW_WRITER) +
			" should have an INFO bookmark",
			findItbBookmark(FW_WRITER, BookmarkType.INFO));
	}

	@Test
	public void firmwareItbIsElectedActive() {
		// The analyzer propagates the active ITB through program
		// context.  Read it at one of the ex9.it sites in either
		// region; the value must match the FW ITB.
		Register itb = program.getLanguage().getRegister("itb");
		assertNotNull("itb register must exist", itb);

		ProgramContext ctx = program.getProgramContext();
		BigInteger romSiteItb =
			ctx.getValue(itb, addr(0x000c), /*signed*/ false);
		BigInteger fwSiteItb =
			ctx.getValue(itb, addr(0x200c), /*signed*/ false);
		assertNotNull("ITB context value should be set at ROM ex9.it site",
			romSiteItb);
		assertNotNull("ITB context value should be set at FW ex9.it site",
			fwSiteItb);
		assertEquals("ROM-region ex9.it should use FW ITB",
			FW_ITB, romSiteItb.longValue());
		assertEquals("FW-region ex9.it should use FW ITB",
			FW_ITB, fwSiteItb.longValue());
	}

	@Test
	public void ex9ItSitesAnnotatedWithFirmwareEntries() {
		// FW IT[0] is `sub r0,r1,r2`.  Both ROM and FW sites with
		// imm=0 should be annotated against the FW entry.
		String romEol = program.getListing()
				.getComment(CodeUnit.EOL_COMMENT, addr(0x000c));
		String fwEol = program.getListing()
				.getComment(CodeUnit.EOL_COMMENT, addr(0x200c));
		assertNotNull("ROM ex9.it 0 should have an EOL comment", romEol);
		assertNotNull("FW ex9.it 0 should have an EOL comment", fwEol);
		assertTrue(
			"ROM ex9.it 0 should be annotated with FW entry (`sub`): " +
				romEol,
			romEol.toLowerCase().contains("sub"));
		assertTrue("FW ex9.it 0 should be annotated with `sub`: " + fwEol,
			fwEol.toLowerCase().contains("sub"));
	}

	private Bookmark findItbBookmark(long off, String bookmarkType) {
		for (Bookmark b : program.getBookmarkManager()
				.getBookmarks(addr(off), bookmarkType)) {
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
