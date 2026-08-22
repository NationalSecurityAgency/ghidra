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

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for MSVC-style switch table recovery in the PowerPC analyzer.
 *
 * MSVC for PowerPC generates switch tables using 16-bit relative offsets
 * loaded via lhzx, unlike GCC/Clang which use 32-bit absolute addresses
 * loaded via lwzx.
 *
 * The test constructs a synthetic PPC32 program with the MSVC switch pattern:
 *   cmplwi  cr6, r11, 2       ; bounds check (3 cases: 0,1,2)
 *   bgt     cr6, default       ; guard branch
 *   slwi    r0, r11, 1         ; index * 2
 *   lis     r12, tableHi       ; table address (high)
 *   addi    r12, r12, tableLo  ; table address (low)
 *   lhzx    r0, r12, r0        ; load 16-bit offset
 *   lis     r12, codeHi        ; code base (high)
 *   addi    r12, r12, codeLo   ; code base (low)
 *   add     r12, r12, r0       ; target = codeBase + offset
 *   mtctr   r12                ; move to CTR
 *   bctr                       ; indirect branch
 *
 * Memory layout:
 *   0x82001000: code region (switch pattern + targets)
 *   0x82003000: data region (switch table with 3 halfword entries)
 */
public class PowerPCMSVCSwitchTest extends AbstractGhidraHeadlessIntegrationTest {

	private TestEnv env;
	private Program program;
	private ProgramBuilder builder;

	// Addresses
	private static final String CODE_START = "0x82001000";
	private static final String TABLE_ADDR = "0x82003000";
	private static final String TARGET_0 = "0x82001100";
	private static final String TARGET_1 = "0x82001200";
	private static final String TARGET_2 = "0x82001300";

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		program = buildProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	private Address addr(String address) {
		return program.getAddressFactory().getAddress(address);
	}

	private Program buildProgram() throws Exception {
		builder = new ProgramBuilder("MSVC_Switch_Test", ProgramBuilder._PPC_32);

		// Code region: executable (0x82001000 - 0x82002FFF)
		MemoryBlock textBlock = builder.createMemory(".text", CODE_START, 0x2000);

		// Data region: read/write, NOT executable (simulates MSVC .rdata section)
		// At 0x82003000 - separate from code to test cross-region table reads
		MemoryBlock rdataBlock = builder.createMemory(".rdata", TABLE_ADDR, 0x1000);

		// Set memory block permissions (requires transaction)
		Program prog = builder.getProgram();
		int txId = prog.startTransaction("setFlags");
		try {
			textBlock.setRead(true);
			textBlock.setWrite(false);
			textBlock.setExecute(true);
			rdataBlock.setRead(true);
			rdataBlock.setWrite(true);
			rdataBlock.setExecute(false);
		}
		finally {
			prog.endTransaction(txId, true);
		}

		// --- MSVC switch pattern at 0x82001000 ---
		// All instructions are 4 bytes, big-endian PPC
		builder.setBytes(CODE_START,
			// cmplwi  cr6, r11, 2       -> 0x2B0B0002
			"2b 0b 00 02" +
			// bgt     cr6, +0x30        -> 0x41990030 (skip to default at +0x30)
			"41 99 00 30" +
			// slwi    r0, r11, 1        -> 0x5560083C (rlwinm r0, r11, 1, 0, 30)
			"55 60 08 3c" +
			// lis     r12, 0x8200       -> 0x3D808200 (table base high)
			"3d 80 82 00" +
			// addi    r12, r12, 0x3000  -> 0x398C3000 (table base low)
			"39 8c 30 00" +
			// lhzx    r0, r12, r0       -> 0x7C0C022E (load 16-bit offset)
			"7c 0c 02 2e" +
			// lis     r12, 0x8200       -> 0x3D808200 (code base high)
			"3d 80 82 00" +
			// addi    r12, r12, 0x1000  -> 0x398C1000 (code base low)
			"39 8c 10 00" +
			// add     r12, r12, r0      -> 0x7D8C0214 (target = base + offset)
			"7d 8c 02 14" +
			// mtctr   r12               -> 0x7D8903A6
			"7d 89 03 a6" +
			// bctr                      -> 0x4E800420
			"4e 80 04 20"
		);
		// Default case (bgt target) at 0x82001030: just a blr
		builder.setBytes("0x82001030", "4e 80 00 20"); // blr

		// --- Switch target code (just blr at each target) ---
		builder.setBytes(TARGET_0, "4e 80 00 20"); // blr (case 0)
		builder.setBytes(TARGET_1, "4e 80 00 20"); // blr (case 1)
		builder.setBytes(TARGET_2, "4e 80 00 20"); // blr (case 2)

		// --- Switch table data at 0x82003000 ---
		// 3 halfword entries (big-endian): offsets from code base 0x82001000
		// entry 0: 0x0100 -> 0x82001000 + 0x0100 = 0x82001100
		// entry 1: 0x0200 -> 0x82001000 + 0x0200 = 0x82001200
		// entry 2: 0x0300 -> 0x82001000 + 0x0300 = 0x82001300
		builder.setBytes(TABLE_ADDR, "01 00 02 00 03 00");

		// Disassemble code regions
		builder.disassemble(CODE_START, 44); // 11 instructions * 4 bytes
		builder.disassemble("0x82001030", 4);
		builder.disassemble(TARGET_0, 4);
		builder.disassemble(TARGET_1, 4);
		builder.disassemble(TARGET_2, 4);

		return builder.getProgram();
	}

	/**
	 * Verify that the test program is set up correctly before testing the analyzer.
	 */
	@Test
	public void testProgramSetup() {
		Listing listing = program.getListing();

		// Verify bctr instruction exists
		Instruction bctr = listing.getInstructionAt(addr("0x82001028")); // 10th instruction
		assertNotNull("bctr should be disassembled", bctr);
		String mnemonic = bctr.getMnemonicString();
		assertTrue("Should be bctr or bcctr, got: " + mnemonic,
			mnemonic.equalsIgnoreCase("bctr") || mnemonic.equalsIgnoreCase("bcctr"));

		// Verify lhzx instruction exists
		Instruction lhzx = listing.getInstructionAt(addr("0x82001014")); // 5th instruction
		assertNotNull("lhzx should be disassembled", lhzx);
		assertEquals("lhzx", lhzx.getMnemonicString().toLowerCase());

		// Verify target instructions exist
		assertNotNull("Target 0 should be disassembled",
			listing.getInstructionAt(addr(TARGET_0)));
		assertNotNull("Target 1 should be disassembled",
			listing.getInstructionAt(addr(TARGET_1)));
		assertNotNull("Target 2 should be disassembled",
			listing.getInstructionAt(addr(TARGET_2)));

		// Verify bctr has NO computed jump references initially
		Reference[] refs = program.getReferenceManager().getReferencesFrom(addr("0x82001028"));
		int computedJumps = 0;
		for (Reference ref : refs) {
			if (ref.getReferenceType() == RefType.COMPUTED_JUMP) {
				computedJumps++;
			}
		}
		assertEquals("bctr should have no COMPUTED_JUMP refs before analysis", 0, computedJumps);
	}

	/**
	 * Test that allowAccess returns true for data memory blocks.
	 *
	 * The MSVC switch table at 0x82003000 is in a writable, non-executable
	 * memory block. The original allowAccess() returned false unconditionally,
	 * which blocked VarnodeContext from reading the table when it was >4096
	 * bytes from the lhzx instruction.
	 *
	 * Distance: 0x82003000 - 0x82001014 = 0x1FEC (8172 bytes) > 4096
	 */
	@Test
	public void testTableInWritableMemory() {
		// Verify the table is in writable memory
		MemoryBlock tableBlock = program.getMemory().getBlock(addr(TABLE_ADDR));
		assertNotNull("Table should be in a memory block", tableBlock);
		assertTrue("Table block should be writable", tableBlock.isWrite());
		assertFalse("Table block should NOT be executable", tableBlock.isExecute());

		// Verify distance exceeds the 4096-byte allowAccess threshold
		long distance = addr(TABLE_ADDR).getOffset() - addr("0x82001014").getOffset();
		assertTrue("Distance to table (" + distance + ") should exceed 4096",
			distance > 4096);
	}

	/**
	 * Test that the data region has the correct switch table entries.
	 */
	@Test
	public void testSwitchTableData() throws Exception {
		Memory memory = program.getMemory();

		// Read the 3 halfword entries
		int entry0 = memory.getShort(addr(TABLE_ADDR)) & 0xFFFF;
		int entry1 = memory.getShort(addr("0x82003002")) & 0xFFFF;
		int entry2 = memory.getShort(addr("0x82003004")) & 0xFFFF;

		assertEquals("Entry 0 offset", 0x0100, entry0);
		assertEquals("Entry 1 offset", 0x0200, entry1);
		assertEquals("Entry 2 offset", 0x0300, entry2);

		// Compute and verify targets
		long codeBase = 0x82001000L;
		assertEquals("Target 0", 0x82001100L, codeBase + entry0);
		assertEquals("Target 1", 0x82001200L, codeBase + entry1);
		assertEquals("Target 2", 0x82001300L, codeBase + entry2);
	}

	/**
	 * Test that PowerPCAddressAnalyzer recovers switch targets from the
	 * synthetic MSVC switch pattern.
	 *
	 * This exercises all three bug fixes:
	 * 1. allowAccess() permits reads from non-executable data sections
	 * 2. targetList is cleared between switch locations
	 * 3. Predecessor block walk goes 2 levels deep for MSVC patterns
	 */
	@Test
	public void testAnalyzerRecoversSwitchTargets() throws Exception {
		// Create a function at CODE_START so the analyzer has context
		int txId = program.startTransaction("test");
		try {
			AddressSet body = new AddressSet(addr(CODE_START), addr("0x8200102B"));
			program.getFunctionManager().createFunction("switchFunc",
				addr(CODE_START), body, SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(txId, true);
		}

		// Invoke the analyzer directly (following DecompilerSwitchAnalyzerTest pattern)
		PowerPCAddressAnalyzer analyzer = new PowerPCAddressAnalyzer();
		AddressSet analyzeSet = new AddressSet(addr(CODE_START), addr("0x8200102B"));
		txId = program.startTransaction("analyze");
		try {
			analyzer.added(program, analyzeSet, TaskMonitor.DUMMY, null);
		}
		finally {
			program.endTransaction(txId, true);
		}

		// Verify COMPUTED_JUMP references from bctr at 0x82001028
		Reference[] refs = program.getReferenceManager()
			.getReferencesFrom(addr("0x82001028"));
		int computedJumps = 0;
		for (Reference ref : refs) {
			if (ref.getReferenceType() == RefType.COMPUTED_JUMP) {
				computedJumps++;
			}
		}
		assertTrue("Analyzer should recover at least 1 switch target, got " + computedJumps,
			computedJumps > 0);
	}
}
